// Package sessiontoken verifies warden's short-lived data-plane admission tokens
// (PASETO v4.public, Ed25519) offline — the broker front door consumes the same
// token the gateway routes on. Verify-only.
//
// ported from warden/internal/sessiontoken (that package is internal/ and
// unimportable across modules) — same precedent as internal/mesh. Keep the
// claim names in sync with warden if the token format changes.
package sessiontoken

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	paseto "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
)

// Claims is the decoded payload the broker needs for routing + impersonation.
type Claims struct {
	SessionID uuid.UUID // jti
	UserID    uuid.UUID // sub — Impersonate-User
	AssetID   uuid.UUID // asset — RoundTrip target
	Protocol  string    // proto — must be "kubernetes"
	Mode      string    // mode — "web" for the no-cnf bearer marker
	Groups    []string  // groups — one Impersonate-Group each
	BrokerID  string    // broker_id — the broker minted into this token
}

// Verifier checks tokens against an Ed25519 public key.
type Verifier struct{ public paseto.V4AsymmetricPublicKey }

// NewVerifier builds a Verifier. A malformed key is a programming error → panic.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	pk, err := paseto.NewV4AsymmetricPublicKeyFromEd25519(pub)
	if err != nil {
		panic(fmt.Sprintf("sessiontoken: invalid ed25519 public key: %v", err))
	}
	return &Verifier{public: pk}
}

// Verify checks the signature + time claims and returns the payload. Fail-closed:
// any error yields a zero Claims.
func (v *Verifier) Verify(token string) (Claims, error) {
	parser := paseto.NewParser() // enforces NotExpired by default
	parser.AddRule(paseto.NotBeforeNbf())
	t, err := parser.ParseV4Public(v.public, token, nil)
	if err != nil {
		return Claims{}, fmt.Errorf("parse token: %w", err)
	}
	jti, err := t.GetJti()
	if err != nil {
		return Claims{}, err
	}
	sid, err := uuid.Parse(jti)
	if err != nil {
		return Claims{}, fmt.Errorf("bad jti: %w", err)
	}
	sub, err := t.GetSubject()
	if err != nil {
		return Claims{}, err
	}
	uid, err := uuid.Parse(sub)
	if err != nil {
		return Claims{}, fmt.Errorf("bad sub: %w", err)
	}
	var assetStr, proto string
	if err := t.Get("asset", &assetStr); err != nil {
		return Claims{}, err
	}
	aid, err := uuid.Parse(assetStr)
	if err != nil {
		return Claims{}, fmt.Errorf("bad asset: %w", err)
	}
	if err := t.Get("proto", &proto); err != nil {
		return Claims{}, err
	}
	mode := optString(t, "mode")
	if proto == "" {
		return Claims{}, errors.New("empty proto")
	}
	var groups []string
	_ = t.Get("groups", &groups) // absent → nil
	return Claims{
		SessionID: sid, UserID: uid, AssetID: aid,
		Protocol: proto, Mode: mode, Groups: groups,
		BrokerID: optString(t, "broker_id"),
	}, nil
}

func optString(t *paseto.Token, key string) string {
	var v string
	_ = t.Get(key, &v)
	return v
}
