package sessiontoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	paseto "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
)

func mintK8s(t *testing.T, priv ed25519.PrivateKey, sub, asset uuid.UUID, groups []string, brokerID string, ttl time.Duration) string {
	t.Helper()
	sk, err := paseto.NewV4AsymmetricSecretKeyFromEd25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	now := time.Now()
	tok.SetIssuedAt(now)
	tok.SetNotBefore(now)
	tok.SetExpiration(now.Add(ttl))
	tok.SetJti(uuid.New().String())
	tok.SetSubject(sub.String())
	_ = tok.Set("asset", asset.String())
	_ = tok.Set("proto", "kubernetes")
	_ = tok.Set("mode", "web")
	_ = tok.Set("login", "")
	_ = tok.Set("cnf", "")
	_ = tok.Set("groups", groups)
	_ = tok.Set("broker_id", brokerID)
	return tok.V4Sign(sk, nil)
}

func TestVerifyReadsK8sClaims(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sub, asset := uuid.New(), uuid.New()
	groups := []string{"developers", "system:masters"}
	tok := mintK8s(t, priv, sub, asset, groups, "broker-0", time.Minute)

	v := sessiontoken.NewVerifier(pub)
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.UserID != sub || c.AssetID != asset || c.Protocol != "kubernetes" || c.BrokerID != "broker-0" {
		t.Fatalf("claims mismatch: %+v", c)
	}
	if len(c.Groups) != 2 || c.Groups[0] != "developers" || c.Groups[1] != "system:masters" {
		t.Fatalf("groups mismatch: %+v", c.Groups)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok := mintK8s(t, priv, uuid.New(), uuid.New(), nil, "b", -time.Minute)
	if _, err := sessiontoken.NewVerifier(pub).Verify(tok); err == nil {
		t.Fatal("expected expired token to fail")
	}
}
