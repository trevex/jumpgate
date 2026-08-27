// Package sessiontoken mints and verifies short-lived data-plane admission tokens
// (PASETO v4.public). The token is a signed, offline-verifiable admission ticket:
// warden holds the Ed25519 private key and mints; the gateway/worker verify with
// the public key alone — no warden round-trip on the hot connect path. The token
// carries only routing/identity claims (nothing secret) plus a `cnf` binding to
// the client's ephemeral SSH key, so a stolen token is useless without the key.
package sessiontoken

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	paseto "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
)

// Claims is the decoded payload of a session token.
type Claims struct {
	SessionID            uuid.UUID // jti — also the live_sessions PK / teardown target
	UserID               uuid.UUID // sub
	AssetID              uuid.UUID // asset
	Protocol             string    // proto, e.g. "ssh"
	Mode                 string    // mode — "web" for browser terminals, empty/"ssh" for the CLI
	Login                string    // login — the target login bound at mint time (web tickets)
	ClientKeyFingerprint string    // cnf — ssh.FingerprintSHA256 of the client's ephemeral key (empty for web)
}

// Minter signs session tokens with an Ed25519 secret key.
type Minter struct{ secret paseto.V4AsymmetricSecretKey }

// NewMinter builds a Minter from an Ed25519 private key. A malformed key is a
// programming error and panics.
func NewMinter(priv ed25519.PrivateKey) *Minter {
	sk, err := paseto.NewV4AsymmetricSecretKeyFromEd25519(priv)
	if err != nil {
		panic(fmt.Sprintf("sessiontoken: invalid ed25519 private key: %v", err))
	}
	return &Minter{secret: sk}
}

// Verifier checks session tokens against an Ed25519 public key.
type Verifier struct{ public paseto.V4AsymmetricPublicKey }

// NewVerifier builds a Verifier from an Ed25519 public key. A malformed key is a
// programming error and panics.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	pk, err := paseto.NewV4AsymmetricPublicKeyFromEd25519(pub)
	if err != nil {
		panic(fmt.Sprintf("sessiontoken: invalid ed25519 public key: %v", err))
	}
	return &Verifier{public: pk}
}

// Mint returns a signed token that expires ttl from now.
func (m *Minter) Mint(c Claims, ttl time.Duration) (string, error) {
	t := paseto.NewToken()
	now := time.Now()
	t.SetIssuedAt(now)
	t.SetNotBefore(now)
	t.SetExpiration(now.Add(ttl))
	t.SetJti(c.SessionID.String())
	t.SetSubject(c.UserID.String())
	if err := t.Set("asset", c.AssetID.String()); err != nil {
		return "", err
	}
	if err := t.Set("proto", c.Protocol); err != nil {
		return "", err
	}
	if err := t.Set("mode", c.Mode); err != nil {
		return "", err
	}
	if err := t.Set("login", c.Login); err != nil {
		return "", err
	}
	if err := t.Set("cnf", c.ClientKeyFingerprint); err != nil {
		return "", err
	}
	return t.V4Sign(m.secret, nil), nil
}

// Verify checks the signature and standard time claims and returns the payload.
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
	var assetStr, proto, cnf string
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
	if err := t.Get("cnf", &cnf); err != nil {
		return Claims{}, err
	}
	// mode and login are optional claims: CLI (cnf-bearing) tokens omit them, so a
	// missing claim decodes as "".
	mode := optString(t, "mode")
	login := optString(t, "login")
	// A web ticket carries no client key, so it legitimately has an empty cnf; any
	// other (SSH/CLI) token must be bound to a client key.
	if mode != "web" && cnf == "" {
		return Claims{}, errors.New("empty cnf")
	}
	return Claims{
		SessionID: sid, UserID: uid, AssetID: aid, Protocol: proto,
		Mode: mode, Login: login, ClientKeyFingerprint: cnf,
	}, nil
}

// optString reads a string claim, treating an absent claim as the empty string
// (older tokens predate the claim) while surfacing nothing on decode errors.
func optString(t *paseto.Token, key string) string {
	var v string
	_ = t.Get(key, &v)
	return v
}
