package oidc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/oidc"
	"github.com/trevex/jumpgate/warden/internal/pgconv"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestResolveOrProvisionJIT(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	prov := oidc.NewProvisioner(pool)
	q := sqlc.New(pool)

	id1, err := prov.ResolveOrProvision(ctx, "https://issuer", "sub-1", oidc.Claims{
		Email: "a@x.com", Name: "Alice", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}

	u, err := q.GetUserByID(ctx, id1)
	if err != nil {
		t.Fatalf("get provisioned user: %v", err)
	}
	if u.Email != "a@x.com" || u.DisplayName != "Alice" {
		t.Fatalf("unexpected user: %+v", u)
	}
	ids, err := q.ListOIDCGroupIDsForUser(ctx, pgconv.UUID(id1))
	if err != nil {
		t.Fatalf("list oidc groups: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected 0 memberships on first provision, got %v", ids)
	}

	// A second call for the same (issuer, subject) resolves to the same user
	// id, not a second JIT-created account.
	id2, err := prov.ResolveOrProvision(ctx, "https://issuer", "sub-1", oidc.Claims{
		Email: "a@x.com", Name: "Alice", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if id2 != id1 {
		t.Fatalf("second provision returned a different user id: %v != %v", id2, id1)
	}
}

func TestResolveOrProvisionEmailCollision(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	prov := oidc.NewProvisioner(pool)
	q := sqlc.New(pool)

	// A local (non-OIDC) account already owns this email.
	if _, err := q.CreateUserFull(ctx, sqlc.CreateUserFullParams{Email: "b@x.com", DisplayName: "B"}); err != nil {
		t.Fatalf("create local user: %v", err)
	}

	// A brand-new (issuer, subject) whose claimed email collides (case-insensitively,
	// exercising auth.NormalizeEmail) must be denied, not merged/hijacked.
	_, err := prov.ResolveOrProvision(ctx, "https://issuer2", "sub-2", oidc.Claims{
		Email: "B@X.com", Name: "B2", EmailVerified: true,
	})
	if !errors.Is(err, oidc.ErrEmailCollision) {
		t.Fatalf("expected ErrEmailCollision, got %v", err)
	}
}

func TestResolveOrProvisionDeactivated(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	prov := oidc.NewProvisioner(pool)
	q := sqlc.New(pool)

	id, err := prov.ResolveOrProvision(ctx, "https://issuer3", "sub-3", oidc.Claims{
		Email: "c@x.com", Name: "C", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := q.DeactivateUser(ctx, id); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	_, err = prov.ResolveOrProvision(ctx, "https://issuer3", "sub-3", oidc.Claims{
		Email: "c@x.com", Name: "C", EmailVerified: true,
	})
	if !errors.Is(err, oidc.ErrDeactivated) {
		t.Fatalf("expected ErrDeactivated, got %v", err)
	}
}

func TestSyncGroups(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	prov := oidc.NewProvisioner(pool)
	q := sqlc.New(pool)

	userID, err := prov.ResolveOrProvision(ctx, "https://issuer4", "sub-4", oidc.Claims{
		Email: "d@x.com", Name: "D", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	g, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "grp-oidc"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE groups SET external_key=$1 WHERE id=$2", "g-ext", g.ID); err != nil {
		t.Fatalf("set external_key: %v", err)
	}

	// A manually-granted membership on a different group must survive every
	// SyncGroups call below untouched.
	manualGroup, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "grp-manual"})
	if err != nil {
		t.Fatalf("create manual group: %v", err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: manualGroup.ID, MemberUserID: pgconv.UUID(userID)}); err != nil {
		t.Fatalf("add manual membership: %v", err)
	}

	assertManualIntact := func(t *testing.T) {
		t.Helper()
		var origin string
		err := pool.QueryRow(ctx, "SELECT origin FROM group_memberships WHERE group_id=$1 AND member_user_id=$2", manualGroup.ID, userID).Scan(&origin)
		if err != nil {
			t.Fatalf("manual membership missing: %v", err)
		}
		if origin != "manual" {
			t.Fatalf("manual membership origin changed to %q", origin)
		}
	}

	// Unmatched claim values are ignored; no memberships appear.
	if err := prov.SyncGroups(ctx, userID, []string{"no-such-group"}); err != nil {
		t.Fatalf("sync unmatched: %v", err)
	}
	ids, err := q.ListOIDCGroupIDsForUser(ctx, pgconv.UUID(userID))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no oidc memberships for unmatched claim, got %v", ids)
	}
	assertManualIntact(t)

	// A matched claim value adds an oidc-origin membership.
	if err := prov.SyncGroups(ctx, userID, []string{"g-ext"}); err != nil {
		t.Fatalf("sync add: %v", err)
	}
	ids, err = q.ListOIDCGroupIDsForUser(ctx, pgconv.UUID(userID))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 1 || ids[0] != g.ID {
		t.Fatalf("ids = %v, want [%v]", ids, g.ID)
	}
	assertManualIntact(t)

	// An empty claim set removes it again.
	if err := prov.SyncGroups(ctx, userID, nil); err != nil {
		t.Fatalf("sync remove: %v", err)
	}
	ids, err = q.ListOIDCGroupIDsForUser(ctx, pgconv.UUID(userID))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no oidc memberships after removal, got %v", ids)
	}
	assertManualIntact(t)
}
