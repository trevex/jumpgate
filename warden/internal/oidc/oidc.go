// Package oidc verifies OIDC ID tokens (Auth-Code + PKCE), JIT-provisions
// jumpgate users keyed on (issuer, subject), and reconciles IdP-group
// membership. It has no HTTP handlers: callers drive AuthCodeURL/Exchange
// from the login/callback endpoints and Provision/SyncGroups from there.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// Config configures the OIDC Service against a single issuer/client.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	GroupsClaim  string
	Scopes       []string
}

// Claims is the subset of ID-token claims the rest of warden cares about.
type Claims struct {
	Subject       string
	Email         string
	Name          string
	EmailVerified bool
	Groups        []string
}

// Sentinel errors. Callers (the HTTP layer) map these to user-facing
// responses; they must never be papered over into a successful login.
var (
	// ErrUnverifiedEmail: the IdP did not assert email_verified=true.
	ErrUnverifiedEmail = errors.New("oidc: id token email is not verified")
	// ErrEmailCollision: JIT provisioning would collide with an existing
	// local/other-issuer account on the same email.
	ErrEmailCollision = errors.New("oidc: email already in use by another account")
	// ErrDeactivated: the resolved user account is deactivated.
	ErrDeactivated = errors.New("oidc: user account is deactivated")
	// ErrStateMismatch: the callback's state param didn't match the sealed
	// cookie, or the sealed cookie failed to open (tampered/expired/wrong AAD).
	ErrStateMismatch = errors.New("oidc: state mismatch")
	// ErrNonceMismatch: the ID token's nonce didn't match the one minted for
	// this login attempt (replay/token-substitution defense).
	ErrNonceMismatch = errors.New("oidc: nonce mismatch")
	// ErrNoIDToken: the token response carried no id_token.
	ErrNoIDToken = errors.New("oidc: token response missing id_token")
)

// stateData is sealed into the login-flow cookie so it survives the redirect
// round trip without server-side session storage.
type stateData struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// Service drives one OIDC issuer/client's auth-code+PKCE flow.
type Service struct {
	cfg      Config
	verifier *gooidc.IDTokenVerifier
	oauth    oauth2.Config
	sealer   *secrets.Sealer
	prov     *Provisioner
}

// New performs OIDC discovery against cfg.IssuerURL (fails closed if the
// issuer is unreachable or malformed) and builds a Service ready to drive
// logins.
func New(ctx context.Context, cfg Config, sealer *secrets.Sealer, prov *Provisioner) (*Service, error) {
	p, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer %q: %w", cfg.IssuerURL, err)
	}
	return &Service{
		cfg:      cfg,
		verifier: p.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		sealer: sealer,
		prov:   prov,
	}, nil
}

// IssuerURL returns the configured issuer, e.g. for audit-event attribution.
func (s *Service) IssuerURL() string { return s.cfg.IssuerURL }

// AuthCodeURL mints a fresh state/nonce/PKCE verifier, seals them into a
// cookie value, and returns both the IdP redirect URL and the sealed cookie
// value (base64url, safe to set as a cookie). The caller sets gotState from
// the callback's ?state= and sealedState from the cookie, and passes both to
// Exchange.
func (s *Service) AuthCodeURL() (authURL, sealedState string, err error) {
	sd := stateData{
		State:    oauth2.GenerateVerifier(),
		Nonce:    oauth2.GenerateVerifier(),
		Verifier: oauth2.GenerateVerifier(),
	}
	pt, err := json.Marshal(sd)
	if err != nil {
		return "", "", fmt.Errorf("oidc: marshal state: %w", err)
	}
	sealed, err := s.sealer.Seal(pt, secrets.AADOIDCState())
	if err != nil {
		return "", "", fmt.Errorf("oidc: seal state: %w", err)
	}
	authURL = s.oauth.AuthCodeURL(sd.State, gooidc.Nonce(sd.Nonce), oauth2.S256ChallengeOption(sd.Verifier))
	return authURL, base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Exchange verifies the callback: opens the sealed state cookie, checks the
// state param matches (CSRF defense), exchanges the code for tokens using the
// bound PKCE verifier, verifies+parses the ID token, and checks the nonce
// matches (replay defense). It returns the verified claims on success.
//
// Fail-closed by construction: every check returns before any network call
// that would otherwise proceed, and a failure at any step aborts the login.
func (s *Service) Exchange(ctx context.Context, sealedState, gotState, code string) (*Claims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealedState)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateMismatch, err)
	}
	pt, err := s.sealer.Open(raw, secrets.AADOIDCState())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateMismatch, err)
	}
	var sd stateData
	if err := json.Unmarshal(pt, &sd); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateMismatch, err)
	}
	// Constant-time-insensitive compare is fine here: state is single-use
	// (bound to a fresh sealed cookie per attempt) and this is not a secret
	// comparison against a static credential.
	if gotState == "" || gotState != sd.State {
		return nil, ErrStateMismatch
	}

	tok, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(sd.Verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, ErrNoIDToken
	}
	idt, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if idt.Nonce != sd.Nonce {
		return nil, ErrNonceMismatch
	}

	var raw2 map[string]any
	if err := idt.Claims(&raw2); err != nil {
		return nil, fmt.Errorf("oidc: parse claims: %w", err)
	}
	c := &Claims{
		Subject:       idt.Subject,
		Email:         stringClaim(raw2, "email"),
		Name:          stringClaim(raw2, "name"),
		EmailVerified: raw2["email_verified"] == true,
		Groups:        extractGroups(raw2, s.cfg.GroupsClaim),
	}
	if !c.EmailVerified {
		return nil, ErrUnverifiedEmail
	}
	return c, nil
}

// Provision resolves an existing (issuer, subject) identity to its user id,
// or JIT-provisions a new local user + identity on first login.
func (s *Service) Provision(ctx context.Context, issuer, subject string, c Claims) (uuid.UUID, error) {
	return s.prov.ResolveOrProvision(ctx, issuer, subject, c)
}

// SyncGroups reconciles userID's OIDC-origin group memberships to exactly
// match groups (IdP group claim values mapped through groups.external_key).
func (s *Service) SyncGroups(ctx context.Context, userID uuid.UUID, groups []string) error {
	return s.prov.SyncGroups(ctx, userID, groups)
}

func stringClaim(raw map[string]any, key string) string {
	v, _ := raw[key].(string)
	return v
}

// extractGroups reads the configured groups claim and coerces a []any of
// strings to []string. Absent claim, wrong type, or empty list all yield nil
// — a misconfigured/absent groups claim degrades to "no group sync", not an
// error, since not every IdP asserts group membership.
func extractGroups(raw map[string]any, claim string) []string {
	if claim == "" {
		return nil
	}
	v, ok := raw[claim].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, e := range v {
		if str, ok := e.(string); ok && str != "" {
			out = append(out, str)
		}
	}
	return out
}
