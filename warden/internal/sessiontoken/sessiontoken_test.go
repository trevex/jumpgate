package sessiontoken

import (
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testSSHPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestMintVerifyRoundTrip(t *testing.T) {
	pub, priv := testKeypair(t)
	m := NewMinter(priv)
	v := NewVerifier(pub)

	sshPub := testSSHPub(t)
	claims := Claims{
		SessionID:            uuid.New(),
		UserID:               uuid.New(),
		AssetID:              uuid.New(),
		Protocol:             "ssh",
		ClientKeyFingerprint: ssh.FingerprintSHA256(sshPub),
	}
	tok, err := m.Mint(claims, 60*time.Second)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.SessionID != claims.SessionID || got.UserID != claims.UserID ||
		got.AssetID != claims.AssetID || got.Protocol != "ssh" ||
		got.ClientKeyFingerprint != claims.ClientKeyFingerprint {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, claims)
	}
}

func TestMintVerifyWebClaims(t *testing.T) {
	pub, priv := testKeypair(t)
	m := NewMinter(priv)
	v := NewVerifier(pub)

	claims := Claims{
		SessionID:            uuid.New(),
		UserID:               uuid.New(),
		AssetID:              uuid.New(),
		Protocol:             "ssh",
		Mode:                 "web",
		Login:                "deploy",
		ClientKeyFingerprint: "",
	}
	tok, err := m.Mint(claims, 60*time.Second)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Mode != "web" {
		t.Fatalf("mode = %q, want web", got.Mode)
	}
	if got.Login != "deploy" {
		t.Fatalf("login = %q, want deploy", got.Login)
	}
	if got.ClientKeyFingerprint != "" {
		t.Fatalf("cnf = %q, want empty", got.ClientKeyFingerprint)
	}
	if got.SessionID != claims.SessionID || got.UserID != claims.UserID ||
		got.AssetID != claims.AssetID || got.Protocol != "ssh" {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, claims)
	}
}

func TestVerifyLegacyCnfTokenHasEmptyMode(t *testing.T) {
	pub, priv := testKeypair(t)
	m := NewMinter(priv)
	v := NewVerifier(pub)

	sshPub := testSSHPub(t)
	tok, err := m.Mint(Claims{
		SessionID:            uuid.New(),
		UserID:               uuid.New(),
		AssetID:              uuid.New(),
		Protocol:             "ssh",
		ClientKeyFingerprint: ssh.FingerprintSHA256(sshPub),
	}, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Mode != "" {
		t.Fatalf("mode = %q, want empty for legacy token", got.Mode)
	}
	if got.Login != "" {
		t.Fatalf("login = %q, want empty for legacy token", got.Login)
	}
	if got.ClientKeyFingerprint == "" {
		t.Fatal("legacy cnf must round-trip non-empty")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := testKeypair(t)
	otherPub, _ := testKeypair(t)
	tok, _ := NewMinter(priv).Mint(Claims{SessionID: uuid.New(), UserID: uuid.New(), AssetID: uuid.New(), Protocol: "ssh", ClientKeyFingerprint: "x"}, time.Minute)
	if _, err := NewVerifier(otherPub).Verify(tok); err == nil {
		t.Fatal("verify with wrong public key must fail")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	pub, priv := testKeypair(t)
	tok, _ := NewMinter(priv).Mint(Claims{SessionID: uuid.New(), UserID: uuid.New(), AssetID: uuid.New(), Protocol: "ssh", ClientKeyFingerprint: "x"}, -time.Second)
	if _, err := NewVerifier(pub).Verify(tok); err == nil {
		t.Fatal("expired token must fail")
	}
}

func TestMintVerifyGroupsAndBroker(t *testing.T) {
	pub, priv := testKeypair(t)
	m, v := NewMinter(priv), NewVerifier(pub)
	in := Claims{
		SessionID: uuid.New(), UserID: uuid.New(), AssetID: uuid.New(),
		Protocol: "kubernetes", Mode: "web",
		Groups: []string{"developers", "system:masters"}, BrokerID: "broker-1",
	}
	tok, err := m.Mint(in, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	out, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.Groups, in.Groups) {
		t.Fatalf("groups = %v", out.Groups)
	}
	if out.BrokerID != "broker-1" {
		t.Fatalf("broker = %q", out.BrokerID)
	}
}

// TestVerifyOldTokenNoGroups: a token minted without the new claims verifies
// with nil/empty groups/broker_id (backward compatibility).
func TestVerifyOldTokenNoGroups(t *testing.T) {
	pub, priv := testKeypair(t)
	m, v := NewMinter(priv), NewVerifier(pub)
	tok, _ := m.Mint(Claims{SessionID: uuid.New(), UserID: uuid.New(), AssetID: uuid.New(), Protocol: "ssh", ClientKeyFingerprint: "fp"}, time.Minute)
	out, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if out.Groups != nil || out.BrokerID != "" {
		t.Fatal("expected empty groups/broker")
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	pub, priv := testKeypair(t)
	tok, _ := NewMinter(priv).Mint(Claims{SessionID: uuid.New(), UserID: uuid.New(), AssetID: uuid.New(), Protocol: "ssh", ClientKeyFingerprint: "x"}, time.Minute)
	bad := tok[:len(tok)-2] + "xy"
	if _, err := NewVerifier(pub).Verify(bad); err == nil {
		t.Fatal("tampered token must fail")
	}
}
