package session_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// TestKubernetesSessionIdentityGate proves CreateKubernetesSession is fail-closed on
// target identity: an entitled caller with a connected broker still gets a session
// ONLY when the asset's identity is verified. An unverified status, and a nil gate
// (identity verification unwired), both refuse with ErrIdentityUnverified — blocking
// a NEW session without touching any established tunnel.
func TestKubernetesSessionIdentityGate(t *testing.T) {
	pool := newSessionPool(t)
	sealer := testSealer(t)
	ctx := context.Background()

	ks := session.NewKeyStore(sqlc.New(pool), sealer)
	if err := ks.Init(ctx); err != nil {
		t.Fatalf("keystore init: %v", err)
	}
	priv, _, err := ks.LoadActive(ctx)
	if err != nil {
		t.Fatalf("keystore load: %v", err)
	}
	q := sqlc.New(pool)

	// Entitled caller on a k8s asset whose cluster has a connected broker.
	assetID := seedK8sAsset(t, q)
	email := "gate-" + uuid.NewString() + "@sess"
	seedUser(t, pool, email, "password123", false)
	var uid uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&uid); err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	grantK8sGroup(ctx, t, q, assetID, uid, "developers")
	reg := dataplane.NewRegistry()
	reg.SetTunnels("broker-1", []string{assetID.String()})

	build := func(gate interface {
		Status(context.Context, targetidentity.StatusRequest) (targetidentity.VerificationStatus, error)
	}) *session.Service {
		return session.NewService(q, authz.New(pool), sessiontoken.NewMinter(priv), testGatewayEndpoint, "", false, testSessionTTL, reg, gate)
	}

	t.Run("verified issues a token", func(t *testing.T) {
		out, err := build(stubGate{status: targetidentity.StatusVerified}).CreateKubernetesSession(ctx, uid, assetID)
		if err != nil {
			t.Fatalf("verified CreateKubernetesSession: %v", err)
		}
		if out.Token == "" {
			t.Fatal("verified session returned no token")
		}
	})

	t.Run("unverified is refused fail-closed", func(t *testing.T) {
		_, err := build(stubGate{status: targetidentity.StatusAwaitingApproval}).CreateKubernetesSession(ctx, uid, assetID)
		if !errors.Is(err, session.ErrIdentityUnverified) {
			t.Fatalf("awaiting-approval err = %v, want ErrIdentityUnverified", err)
		}
	})

	t.Run("identity changed is refused", func(t *testing.T) {
		_, err := build(stubGate{status: targetidentity.StatusIdentityChanged}).CreateKubernetesSession(ctx, uid, assetID)
		if !errors.Is(err, session.ErrIdentityUnverified) {
			t.Fatalf("identity-changed err = %v, want ErrIdentityUnverified", err)
		}
	})

	t.Run("nil gate is refused", func(t *testing.T) {
		_, err := build(nil).CreateKubernetesSession(ctx, uid, assetID)
		if !errors.Is(err, session.ErrIdentityUnverified) {
			t.Fatalf("nil-gate err = %v, want ErrIdentityUnverified", err)
		}
	})
}
