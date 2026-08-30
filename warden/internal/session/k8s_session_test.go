package session_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
)

// seedK8sAsset creates a folder + k8s asset and returns its id. Unlike ssh/postgres
// assets, k8s carries no per-asset config/login rows in this slice (Kind alone
// gates CreateKubernetesSession; groups come from held k8s:group:* capabilities).
func seedK8sAsset(t *testing.T, q *sqlc.Queries) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	folder, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "prod-k8s-sess-" + uuid.NewString()})
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	asset, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{FolderID: folder.ID, Name: "k8s-sess", Labels: []byte("{}"), Kind: "k8s"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	return asset.ID
}

// grantK8sGroup creates a role carrying k8s:group:<group> and binds it to uid on
// assetID via a standing role_binding.
func grantK8sGroup(ctx context.Context, t *testing.T, q *sqlc.Queries, assetID, uid uuid.UUID, group string) {
	t.Helper()
	role := createRoleWithCaps(t, ctx, q, "k8s-"+group+"-"+uuid.NewString(), pgtype.UUID{}, `["k8s:group:`+group+`"]`)
	if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
		RoleID: role.ID, ScopeAssetID: pgU(assetID), SubjectUserID: pgU(uid),
	}); err != nil {
		t.Fatalf("CreateRoleBinding: %v", err)
	}
}

// TestCreateKubernetesSession drives the RPC over the wire: an entitled caller on
// a k8s asset with a broker holding its tunnel gets a bearer token carrying the
// materialized groups + broker_id; no entitled group hides behind NotFound; an
// entitled caller whose cluster has no connected broker gets a distinct
// Unavailable (ErrClusterOffline).
func TestCreateKubernetesSession(t *testing.T) {
	reg := dataplane.NewRegistry()
	pool, url, signPub := newServerWithSession(t, reg)
	ctx := context.Background()
	q := sqlc.New(pool)
	client := sessionv1connect.NewSessionServiceClient(http.DefaultClient, url)

	t.Run("entitled caller with connected broker gets groups + broker_id", func(t *testing.T) {
		assetID := seedK8sAsset(t, q)

		email := "k8suser-" + uuid.NewString() + "@sess"
		seedUser(t, pool, email, "password123", false)
		var uid uuid.UUID
		if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&uid); err != nil {
			t.Fatalf("lookup user: %v", err)
		}
		grantK8sGroup(ctx, t, q, assetID, uid, "developers")

		reg.SetTunnels("broker-1", []string{assetID.String()})

		tok := authClient(t, url, email, "password123")
		resp, err := client.CreateKubernetesSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateKubernetesSessionRequest{
			AssetId: assetID.String(),
		}), tok))
		if err != nil {
			t.Fatalf("CreateKubernetesSession: %v", err)
		}
		if resp.Msg.SessionToken == "" {
			t.Fatal("empty session_token")
		}
		if resp.Msg.GatewayEndpoint != testGatewayEndpoint {
			t.Fatalf("gateway_endpoint = %q, want %q", resp.Msg.GatewayEndpoint, testGatewayEndpoint)
		}

		claims, err := sessiontoken.NewVerifier(signPub).Verify(resp.Msg.SessionToken)
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}
		if claims.Protocol != "kubernetes" {
			t.Fatalf("token proto = %q, want kubernetes", claims.Protocol)
		}
		if len(claims.Groups) != 1 || claims.Groups[0] != "developers" {
			t.Fatalf("token groups = %v, want [developers]", claims.Groups)
		}
		if claims.BrokerID != "broker-1" {
			t.Fatalf("token broker_id = %q, want broker-1", claims.BrokerID)
		}
		if claims.UserID != uid || claims.AssetID != assetID {
			t.Fatalf("token user/asset = %s/%s, want %s/%s", claims.UserID, claims.AssetID, uid, assetID)
		}
	})

	t.Run("no entitled group is not found", func(t *testing.T) {
		assetID := seedK8sAsset(t, q)
		reg.SetTunnels("broker-2", []string{assetID.String()})

		email := "k8snogroup-" + uuid.NewString() + "@sess"
		seedUser(t, pool, email, "password123", false)
		tok := authClient(t, url, email, "password123")

		_, err := client.CreateKubernetesSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateKubernetesSessionRequest{
			AssetId: assetID.String(),
		}), tok))
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("no-group CreateKubernetesSession = %v, want NotFound", connect.CodeOf(err))
		}
	})

	t.Run("non-k8s asset is not found", func(t *testing.T) {
		assetID := seedSSHAsset(t, q, []string{"deploy"})
		email := "k8swrongkind-" + uuid.NewString() + "@sess"
		seedUser(t, pool, email, "password123", false)
		var uid uuid.UUID
		if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&uid); err != nil {
			t.Fatalf("lookup user: %v", err)
		}
		grantK8sGroup(ctx, t, q, assetID, uid, "developers")
		tok := authClient(t, url, email, "password123")

		_, err := client.CreateKubernetesSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateKubernetesSessionRequest{
			AssetId: assetID.String(),
		}), tok))
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("non-k8s CreateKubernetesSession = %v, want NotFound", connect.CodeOf(err))
		}
	})

	t.Run("entitled caller with no connected broker is unavailable", func(t *testing.T) {
		assetID := seedK8sAsset(t, q)

		email := "k8soffline-" + uuid.NewString() + "@sess"
		seedUser(t, pool, email, "password123", false)
		var uid uuid.UUID
		if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&uid); err != nil {
			t.Fatalf("lookup user: %v", err)
		}
		grantK8sGroup(ctx, t, q, assetID, uid, "developers")
		// Deliberately no reg.SetTunnels for this asset: no broker holds its tunnel.

		tok := authClient(t, url, email, "password123")
		_, err := client.CreateKubernetesSession(ctx, withToken(connect.NewRequest(&sessionv1.CreateKubernetesSessionRequest{
			AssetId: assetID.String(),
		}), tok))
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("offline-cluster CreateKubernetesSession = %v, want Unavailable", connect.CodeOf(err))
		}
	})
}
