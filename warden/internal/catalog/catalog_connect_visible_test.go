package catalog_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// seedFolderCascade wires an asset reachable ONLY via a FOLDER-scoped ssh:login
// binding (no asset-scoped binding, no catalog:asset:read for the caller): folder
// `fc` ⊃ asset `box` (login demo, kind ca); alice holds ssh:login:demo bound at
// `fc`. Returns alice's email/password and the box asset id.
func seedFolderCascade(t *testing.T, pool *pgxpool.Pool) (aliceEmail, alicePass, boxID string) {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(pool)

	aliceEmail, alicePass = "fc-alice@x", "password123"
	seedUser(t, pool, aliceEmail, alicePass, false)
	alice, err := q.GetUserByEmail(ctx, aliceEmail)
	if err != nil {
		t.Fatal(err)
	}

	fc, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "fc-cascade"})
	if err != nil {
		t.Fatal(err)
	}
	box, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: fc.ID, Name: "fc-box", Labels: []byte("{}"), Kind: "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.UpsertSSHAssetLogin(ctx, sqlc.UpsertSSHAssetLoginParams{AssetID: box.ID, Login: "demo", Kind: "ca"}); err != nil {
		t.Fatal(err)
	}

	// Grant demo (declared on the asset) AND ghost (NOT declared) so entitled_logins
	// can be asserted to intersect down to just demo — the login the asset defines.
	role := createRoleWithCaps(t, ctx, q, "fc-demo", pgtype.UUID{}, `["ssh:login:demo", "ssh:login:ghost"]`)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID:        role.ID,
		ScopeFolderID: pgtype.UUID{Bytes: fc.ID, Valid: true},
		SubjectUserID: pgtype.UUID{Bytes: alice.ID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return aliceEmail, alicePass, box.ID.String()
}

// A folder-cascade caller (alice: folder-scoped ssh:login:demo, no asset binding,
// no catalog:asset:read) must NOT be 404'd by GetAssetAccess; the response carries
// the connect capabilities including ssh:login:demo. A stranger still gets NotFound.
func TestGetAssetAccessConnectVisible(t *testing.T) {
	pool, url := newServer(t)
	aliceEmail, alicePass, boxID := seedFolderCascade(t, pool)
	seedUser(t, pool, "fc-stranger@x", "password123", false)
	ctx := context.Background()
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)

	atok := authClient(t, url, aliceEmail, alicePass)
	acc, err := cat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: boxID}), atok))
	if err != nil {
		t.Fatalf("alice GetAssetAccess: want ok, got %v", err)
	}
	found := false
	for _, c := range acc.Msg.Capabilities {
		if c == "ssh:login:demo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("alice caps missing ssh:login:demo: %v", acc.Msg.Capabilities)
	}
	// entitled_logins is the connect caps ∩ the asset's configured logins: alice
	// holds ssh:login:demo AND ssh:login:ghost, but the asset declares only `demo`,
	// so ghost must be excluded — only usable logins appear.
	if got := acc.Msg.EntitledLogins; len(got) != 1 || got[0] != "demo" {
		t.Fatalf("alice entitled_logins = %v, want [demo] (ghost is not a configured login on the asset)", got)
	}

	// Stranger: neither arm → NotFound (existence hiding preserved).
	stok := authClient(t, url, "fc-stranger@x", "password123")
	_, err = cat.GetAssetAccess(ctx, withToken(connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: boxID}), stok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("stranger GetAssetAccess = %v, want NotFound", connect.CodeOf(err))
	}
}

// ResolveAsset must resolve the box for the folder-cascade caller (connect arm)
// and stay NotFound for a stranger.
func TestResolveAssetConnectVisible(t *testing.T) {
	pool, url := newServer(t)
	aliceEmail, alicePass, boxID := seedFolderCascade(t, pool)
	seedUser(t, pool, "fc-stranger@x", "password123", false)
	ctx := context.Background()
	cat := catalogv1connect.NewCatalogServiceClient(http.DefaultClient, url)

	atok := authClient(t, url, aliceEmail, alicePass)
	got, err := cat.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: boxID}), atok))
	if err != nil {
		t.Fatalf("alice ResolveAsset: want ok, got %v", err)
	}
	if got.Msg.AssetId != boxID {
		t.Fatalf("alice ResolveAsset id = %s, want %s", got.Msg.AssetId, boxID)
	}

	stok := authClient(t, url, "fc-stranger@x", "password123")
	_, err = cat.ResolveAsset(ctx, withToken(connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: boxID}), stok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("stranger ResolveAsset = %v, want NotFound", connect.CodeOf(err))
	}
}
