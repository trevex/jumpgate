package auth_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

func TestOIDCQueries(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	u, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "oidc@x", DisplayName: "O"})
	if err != nil {
		t.Fatal(err)
	}

	if err := q.CreateUserIdentity(ctx, sqlc.CreateUserIdentityParams{
		UserID:  u.ID,
		Issuer:  "https://issuer",
		Subject: "sub-1",
	}); err != nil {
		t.Fatalf("create identity: %v", err)
	}

	got, err := q.GetUserByIdentity(ctx, sqlc.GetUserByIdentityParams{Issuer: "https://issuer", Subject: "sub-1"})
	if err != nil {
		t.Fatalf("get by identity: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("got.ID = %v, want %v", got.ID, u.ID)
	}

	if _, err := q.GetUserByIdentity(ctx, sqlc.GetUserByIdentityParams{Issuer: "https://issuer", Subject: "unknown-sub"}); err == nil {
		t.Fatal("expected error for unknown identity")
	}

	g, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "grp1"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE groups SET external_key=$1 WHERE id=$2", "ext-1", g.ID); err != nil {
		t.Fatalf("set external_key: %v", err)
	}
	gotGroup, err := q.GetGroupByExternalKey(ctx, pgtype.Text{String: "ext-1", Valid: true})
	if err != nil {
		t.Fatalf("get by external key: %v", err)
	}
	if gotGroup.ID != g.ID {
		t.Fatalf("gotGroup.ID = %v, want %v", gotGroup.ID, g.ID)
	}

	memberUserID := pgtype.UUID{Bytes: u.ID, Valid: true}

	if err := q.AddUserToGroupWithOrigin(ctx, sqlc.AddUserToGroupWithOriginParams{
		GroupID:      g.ID,
		MemberUserID: memberUserID,
		Origin:       "oidc",
	}); err != nil {
		t.Fatalf("add with origin: %v", err)
	}
	ids, err := q.ListOIDCGroupIDsForUser(ctx, memberUserID)
	if err != nil {
		t.Fatalf("list oidc groups: %v", err)
	}
	if len(ids) != 1 || ids[0] != g.ID {
		t.Fatalf("ids = %v, want [%v]", ids, g.ID)
	}

	// Re-adding is a no-op (ON CONFLICT DO NOTHING).
	if err := q.AddUserToGroupWithOrigin(ctx, sqlc.AddUserToGroupWithOriginParams{
		GroupID:      g.ID,
		MemberUserID: memberUserID,
		Origin:       "oidc",
	}); err != nil {
		t.Fatalf("re-add with origin: %v", err)
	}
	ids, err = q.ListOIDCGroupIDsForUser(ctx, memberUserID)
	if err != nil {
		t.Fatalf("list oidc groups after re-add: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("ids after re-add = %v, want len 1", ids)
	}

	if err := q.DeleteOIDCMembership(ctx, sqlc.DeleteOIDCMembershipParams{MemberUserID: memberUserID, GroupID: g.ID}); err != nil {
		t.Fatalf("delete oidc membership: %v", err)
	}
	ids, err = q.ListOIDCGroupIDsForUser(ctx, memberUserID)
	if err != nil {
		t.Fatalf("list oidc groups after delete: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ids after delete = %v, want empty", ids)
	}

	// A manual membership (via the existing AddUserToGroup query) must not show
	// up as an OIDC-origin membership.
	g2, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "grp2"})
	if err != nil {
		t.Fatalf("create group 2: %v", err)
	}
	if err := q.AddUserToGroup(ctx, sqlc.AddUserToGroupParams{GroupID: g2.ID, MemberUserID: memberUserID}); err != nil {
		t.Fatalf("add manual: %v", err)
	}
	ids, err = q.ListOIDCGroupIDsForUser(ctx, memberUserID)
	if err != nil {
		t.Fatalf("list oidc groups after manual add: %v", err)
	}
	for _, id := range ids {
		if id == g2.ID {
			t.Fatalf("manual membership leaked into OIDC-origin list: %v", ids)
		}
	}
}
