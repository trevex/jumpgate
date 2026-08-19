// Package dataplane holds the warden-side domain logic that backs the data-plane
// (gateway/worker) RPCs: redeeming a session token to establish a live session.
//
// SetupSession is the session-setup authorization gate. A worker presents a
// session token (minted by CreateSession) plus the client's ephemeral SSH key.
// warden: verifies the token signature/time claims, checks the client key
// matches the token's `cnf` binding, RE-CHECKS the login entitlement (defense in
// depth — a grant revoked between mint and connect is caught here), records a
// live_sessions row (PK = session_id = replay guard) and a session.started audit
// event IN THE SAME TX, commits, then issues a short-lived JIT SSH certificate
// via the credential broker.
package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/pgerr"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// Sentinel errors returned by Setup (Task 8 maps them to Connect codes).
var (
	ErrBadToken      = errors.New("invalid session token")
	ErrKeyMismatch   = errors.New("client key does not match token binding")
	ErrNotAuthorized = errors.New("no login entitlement on asset")
	ErrReplay        = errors.New("session already set up")
	ErrNoTarget      = errors.New("asset has no target address")
)

// SetupService redeems session tokens and records live sessions.
type SetupService struct {
	pool       *pgxpool.Pool
	verifier   *sessiontoken.Verifier
	authz      authz.Authorizer
	broker     *vault.Broker
	audit      *audit.Logger
	certMaxTTL time.Duration
}

// NewSetupService builds the session-setup service.
func NewSetupService(pool *pgxpool.Pool, v *sessiontoken.Verifier, a authz.Authorizer, b *vault.Broker, log *audit.Logger, certMaxTTL time.Duration) *SetupService {
	return &SetupService{pool: pool, verifier: v, authz: a, broker: b, audit: log, certMaxTTL: certMaxTTL}
}

// SetupResult is the successful outcome.
type SetupResult struct {
	TargetAddress  string
	SSHCertificate []byte
	SessionID      string
}

// Setup verifies the token, re-checks authorization, records the live session (with
// the session.started audit event) in one tx, then issues the JIT SSH cert. The
// re-check is defense-in-depth over the admission token; the live_sessions PK is
// the replay guard.
func (s *SetupService) Setup(ctx context.Context, rawToken, workerID string, clientPub, targetPub []byte) (SetupResult, error) {
	claims, err := s.verifier.Verify(rawToken)
	if err != nil {
		return SetupResult{}, ErrBadToken
	}
	// Kc — the client's ephemeral key — must match the token's cnf binding.
	pub, err := parseSSHPublicKey(clientPub)
	if err != nil {
		return SetupResult{}, ErrBadToken
	}
	if ssh.FingerprintSHA256(pub) != claims.ClientKeyFingerprint {
		return SetupResult{}, ErrKeyMismatch
	}
	// Kw — the worker's per-session key — is what we certify for the target hop.
	if _, err := parseSSHPublicKey(targetPub); err != nil {
		return SetupResult{}, ErrBadToken
	}

	cfg, err := gen.New(s.pool).GetSSHAssetConfig(ctx, claims.AssetID)
	if err != nil {
		return SetupResult{}, fmt.Errorf("get ssh asset config: %w", err)
	}
	if cfg.TargetAddress == "" {
		return SetupResult{}, ErrNoTarget
	}
	logins, err := authz.EntitledLogins(ctx, s.authz, claims.UserID, claims.AssetID, cfg.AllowedLogins)
	if err != nil {
		return SetupResult{}, err
	}
	if len(logins) == 0 {
		return SetupResult{}, ErrNotAuthorized
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SetupResult{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := gen.New(tx)
	// GrantID is intentionally omitted (zero value pgtype.UUID{} → NULL): teardown
	// re-evaluates the held-role closure, so the grant link is an unused
	// optimization in M4a.
	if _, err := q.InsertLiveSession(ctx, gen.InsertLiveSessionParams{
		ID:          claims.SessionID,
		UserID:      claims.UserID,
		AssetID:     claims.AssetID,
		WorkerID:    workerID,
		Protocol:    "ssh",
		Principals:  logins,
		ClientKeyFp: claims.ClientKeyFingerprint,
	}); err != nil {
		if pgerr.IsUniqueViolation(err) {
			return SetupResult{}, ErrReplay
		}
		return SetupResult{}, fmt.Errorf("insert live session: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{
		"session_id": claims.SessionID.String(),
		"user_id":    claims.UserID.String(),
		"asset_id":   claims.AssetID.String(),
		"worker_id":  workerID,
		"principals": logins,
	})
	// The session.started event rides the SAME tx as the live_sessions insert, so
	// the session is recorded and audited atomically (via the outbox Enqueue).
	if err := s.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventSessionStarted,
		ActorID: claims.UserID,
		Subject: "live_session:" + claims.SessionID.String(),
		Details: detail,
	}); err != nil {
		return SetupResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SetupResult{}, fmt.Errorf("commit: %w", err)
	}

	// Cert issuance is POST-COMMIT: the session is already recorded, so a
	// cert-issue failure returns an error but leaves the recorded session in
	// place — acceptable, the worker retry / teardown reconciles it.
	creds, err := s.broker.Issue(ctx, claims.UserID, claims.AssetID, vault.IssueRequest{
		ClientSSHPubKey: targetPub,
		ValidUntil:      time.Now().Add(s.certMaxTTL),
		KeyID:           claims.SessionID.String(),
	})
	if err != nil {
		return SetupResult{}, fmt.Errorf("issue credential: %w", err)
	}
	var cert []byte
	for _, c := range creds {
		if c.Kind == "ssh-cert" {
			cert = c.SSHCertificate
		}
	}
	return SetupResult{TargetAddress: cfg.TargetAddress, SSHCertificate: cert, SessionID: claims.SessionID.String()}, nil
}

// parseSSHPublicKey accepts authorized_keys text or raw wire form (copy of the
// broker's helper).
func parseSSHPublicKey(raw []byte) (ssh.PublicKey, error) {
	if pub, _, _, _, err := ssh.ParseAuthorizedKey(raw); err == nil {
		return pub, nil
	}
	return ssh.ParsePublicKey(raw)
}
