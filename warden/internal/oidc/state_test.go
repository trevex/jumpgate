package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// testSealer builds a real Sealer over a fixed 32-byte test key.
func testSealer(t *testing.T) *secrets.Sealer {
	t.Helper()
	s, err := secrets.NewSealer(make([]byte, 32))
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}
	return s
}

// TestStateSealRoundTrip exercises the sealed-state blob directly (the
// unexported stateData type + secrets.AADOIDCState binding used by
// AuthCodeURL/Exchange), without any network call.
func TestStateSealRoundTrip(t *testing.T) {
	sealer := testSealer(t)
	sd := stateData{State: "s1", Nonce: "n1", Verifier: "v1", CLIRedirect: "http://127.0.0.1:5555/cb"}

	pt, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sealed, err := sealer.Seal(pt, secrets.AADOIDCState())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	opened, err := sealer.Open(sealed, secrets.AADOIDCState())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var got stateData
	if err := json.Unmarshal(opened, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != sd {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, sd)
	}

	// Tampering with any byte of the sealed blob must fail closed.
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := sealer.Open(tampered, secrets.AADOIDCState()); err == nil {
		t.Fatal("expected tampered blob to fail to open")
	}

	// A different AAD (wrong purpose binding) must fail closed too.
	if _, err := sealer.Open(sealed, []byte("some-other-purpose")); err == nil {
		t.Fatal("expected wrong-AAD open to fail")
	}
}

// TestExchangeStateMismatch drives the real Service.AuthCodeURL/Exchange up
// to (but never past) the state comparison, so it never makes a network call:
// Exchange checks the sealed-state cookie and the state param before it ever
// calls the token endpoint.
func TestExchangeStateMismatch(t *testing.T) {
	svc := &Service{sealer: testSealer(t)}
	ctx := context.Background()

	authURL, sealedState, err := svc.AuthCodeURL()
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	correctState := u.Query().Get("state")
	if correctState == "" {
		t.Fatal("auth url has no state param")
	}

	// Wrong state param: must fail before any network attempt.
	if _, _, err := svc.Exchange(ctx, sealedState, "not-the-right-state", "code"); err == nil {
		t.Fatal("expected state mismatch error")
	} else if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}

	// Malformed (non-base64) sealed cookie value.
	if _, _, err := svc.Exchange(ctx, "not-valid-base64!!", correctState, "code"); err == nil {
		t.Fatal("expected decode error for malformed sealed state")
	} else if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}

	// Tampered sealed cookie value (valid base64, but Open fails).
	raw, err := base64.RawURLEncoding.DecodeString(sealedState)
	if err != nil {
		t.Fatalf("decode sealed state: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	tamperedSealed := base64.RawURLEncoding.EncodeToString(raw)
	if _, _, err := svc.Exchange(ctx, tamperedSealed, correctState, "code"); err == nil {
		t.Fatal("expected open error for tampered sealed state")
	} else if !errors.Is(err, ErrStateMismatch) {
		t.Fatalf("expected ErrStateMismatch, got %v", err)
	}
}

// TestAuthCodeURLCLISealsRedirect drives the real Service.AuthCodeURLCLI and
// confirms it seals successfully and returns a non-empty authURL/sealedState
// carrying the CLI loopback redirect, without any network call. The seal/open
// round trip itself (including CLIRedirect) is covered directly by
// TestStateSealRoundTrip.
func TestAuthCodeURLCLISealsRedirect(t *testing.T) {
	svc := &Service{sealer: testSealer(t)}

	authURL, sealedState, err := svc.AuthCodeURLCLI("http://127.0.0.1:5555/cb")
	if err != nil {
		t.Fatalf("AuthCodeURLCLI: %v", err)
	}
	if authURL == "" {
		t.Fatal("authURL is empty")
	}
	if sealedState == "" {
		t.Fatal("sealedState is empty")
	}
}
