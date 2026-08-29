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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// Sentinel errors returned by Setup; the RPC layer maps them to Connect codes.
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
	authz      *authz.Authorizer
	broker     *vault.Broker
	audit      *audit.Logger
	certMaxTTL time.Duration
}

// NewSetupService builds the session-setup service.
func NewSetupService(pool *pgxpool.Pool, v *sessiontoken.Verifier, a *authz.Authorizer, b *vault.Broker, log *audit.Logger, certMaxTTL time.Duration) *SetupService {
	return &SetupService{pool: pool, verifier: v, authz: a, broker: b, audit: log, certMaxTTL: certMaxTTL}
}

// SetupResult is the successful outcome. The credential is discriminated by
// CredentialKind ("ssh-cert" | "ssh-password" | "ssh-key" | "x509" |
// "pg-password"); exactly one of the credential fields is populated.
type SetupResult struct {
	TargetAddress      string
	CredentialKind     string
	SSHCertificate     []byte
	Password           string
	PrivateKey         []byte
	SessionID          string
	RecordingRequired  bool
	RecordingObjectKey string
	// TargetHostKey is the asset's configured host-key pin (an OpenSSH
	// authorized_keys-style public-key line), or empty when unset. The worker
	// fails closed on a mismatch when it is non-empty; empty = accept-and-log.
	TargetHostKey string
	// GrantID is the authorizing JIT grant when exactly one active grant covers
	// (user, asset); empty for standing (zero grants) or ambiguous (multiple).
	GrantID string

	X509Certificate []byte // postgres mtls: client leaf cert PEM
	X509PrivateKey  []byte // postgres mtls: client key PEM
	TargetServerCA  string // postgres: target server CA PEM (mTLS verify-full)
	DefaultDatabase string // postgres: default database
}

// capRecordExempt, when held on the asset, permits an unrecorded SSH session.
const capRecordExempt = "ssh:record:exempt"

// recordingObjectKey is the date-partitioned object key for a session recording.
// The protocol segment keeps one bucket usable across protocols.
func recordingObjectKey(sessionID uuid.UUID, at time.Time) string {
	u := at.UTC()
	return fmt.Sprintf("recordings/ssh/%04d/%02d/%02d/%s.cast", u.Year(), u.Month(), u.Day(), sessionID.String())
}

// Setup verifies the token, re-checks authorization, records the live session (with
// the session.started audit event) in one tx, then issues the JIT SSH cert. The
// re-check is defense-in-depth over the admission token; the live_sessions PK is
// the replay guard.
func (s *SetupService) Setup(ctx context.Context, rawToken, workerID, login string, clientPub, targetPub []byte) (SetupResult, error) {
	claims, err := s.verifier.Verify(rawToken)
	if err != nil {
		return SetupResult{}, ErrBadToken
	}
	// Web tickets carry no client key: the browser has no SSH key to prove, and the
	// login is bound in the token (authoritative — the ticket-mint already checked
	// the login entitlement). So the cnf/Kc proof is skipped and the request's
	// client key + login are ignored in favor of the claim. cnf-bearing (CLI)
	// tokens keep the client-key proof and honor the request's login. Everything
	// after this — re-authorization and target-credential issuance over Kw — is
	// identical for both paths.
	if claims.Mode == "web" {
		login = claims.Login
	} else {
		// Kc — the client's ephemeral key — must match the token's cnf binding.
		pub, err := parseSSHPublicKey(clientPub)
		if err != nil {
			return SetupResult{}, ErrBadToken
		}
		if ssh.FingerprintSHA256(pub) != claims.ClientKeyFingerprint {
			return SetupResult{}, ErrKeyMismatch
		}
	}
	q0 := sqlc.New(s.pool)
	// Fetch the user's data-plane capability set for the asset ONCE (one closure
	// query) and derive BOTH the login entitlement and the record-exemption from it.
	// This re-checks the requested login against the live held-closure (defense in
	// depth over the admission token). ConnectCapabilities uses the full scope
	// cascade (global + ancestor folders + asset) minus the literal `**` carve-out,
	// exactly matching the CreateSession mint — otherwise a folder-cascade session
	// would mint then be denied here. The broker independently re-enforces this too.
	caps, err := authz.ConnectCapabilities(ctx, s.authz, claims.UserID, claims.AssetID)
	if err != nil {
		return SetupResult{}, err
	}

	// Per-protocol: resolve the target config, the allowed logins, the connect
	// predicate, recording policy, and (SSH only) the Kw check.
	var (
		targetAddress, targetHostKey, targetServerCA, defaultDB string
		allowed                                                 []string
		recordingRequired                                       bool
		recordingKey                                            string
		protocol                                                = claims.Protocol
	)
	switch claims.Protocol {
	case "postgres":
		cfg, err := q0.GetPostgresAssetConfig(ctx, claims.AssetID)
		if err != nil {
			return SetupResult{}, fmt.Errorf("get postgres asset config: %w", err)
		}
		if cfg.TargetAddress == "" {
			return SetupResult{}, ErrNoTarget
		}
		targetAddress, targetServerCA, defaultDB = cfg.TargetAddress, cfg.TargetServerCa, cfg.DefaultDatabase
		rows, err := q0.ListPostgresAssetLogins(ctx, claims.AssetID)
		if err != nil {
			return SetupResult{}, fmt.Errorf("list postgres asset logins: %w", err)
		}
		for _, r := range rows {
			allowed = append(allowed, r.Role)
		}
		if !containsLogin(caps.EntitledLoginsFor(authz.DBLoginPrefix, allowed), login) {
			return SetupResult{}, ErrNotAuthorized
		}
		// Recording is deferred for postgres (no recorder yet); never required.
		recordingRequired, recordingKey = false, ""
	default: // "ssh" (empty proto = legacy ssh)
		protocol = "ssh"
		if _, err := parseSSHPublicKey(targetPub); err != nil {
			return SetupResult{}, ErrBadToken
		}
		cfg, err := q0.GetSSHAssetConfig(ctx, claims.AssetID)
		if err != nil {
			return SetupResult{}, fmt.Errorf("get ssh asset config: %w", err)
		}
		if cfg.TargetAddress == "" {
			return SetupResult{}, ErrNoTarget
		}
		targetAddress, targetHostKey = cfg.TargetAddress, cfg.HostPublicKey
		rows, err := q0.ListSSHAssetLogins(ctx, claims.AssetID)
		if err != nil {
			return SetupResult{}, fmt.Errorf("list ssh asset logins: %w", err)
		}
		for _, r := range rows {
			allowed = append(allowed, r.Login)
		}
		if !containsLogin(caps.EntitledLogins(allowed), login) {
			return SetupResult{}, ErrNotAuthorized
		}
		recordingRequired = !caps.Allows(capRecordExempt)
		recordingKey = recordingObjectKey(claims.SessionID, time.Now())
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SetupResult{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	// Attribute the session to its authorizing JIT grant when exactly one active
	// grant covers (user, asset). Zero (standing binding) or multiple (ambiguous)
	// active grants leave grant_id NULL — the attribution must be unambiguous.
	var grantID pgtype.UUID
	ids, err := q.ActiveGrantIDsForUserAsset(ctx, sqlc.ActiveGrantIDsForUserAssetParams{
		SubjectUserID: claims.UserID,
		ScopeAssetID:  claims.AssetID,
	})
	if err != nil {
		return SetupResult{}, fmt.Errorf("resolve grant: %w", err)
	}
	if len(ids) == 1 {
		grantID = pgtype.UUID{Bytes: ids[0], Valid: true}
	}
	if _, err := q.InsertLiveSession(ctx, sqlc.InsertLiveSessionParams{
		ID:          claims.SessionID,
		UserID:      claims.UserID,
		AssetID:     claims.AssetID,
		WorkerID:    workerID,
		GrantID:     grantID,
		Protocol:    protocol,
		Principals:  []string{login},
		ClientKeyFp: claims.ClientKeyFingerprint,
	}); err != nil {
		if apierr.IsUniqueViolation(err) {
			return SetupResult{}, ErrReplay
		}
		return SetupResult{}, fmt.Errorf("insert live session: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{
		"session_id": claims.SessionID.String(),
		"user_id":    claims.UserID.String(),
		"asset_id":   claims.AssetID.String(),
		"worker_id":  workerID,
		"login":      login,
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
	cred, err := s.broker.Issue(ctx, claims.UserID, claims.AssetID, vault.IssueRequest{
		Login:           login,
		ClientSSHPubKey: targetPub,
		ValidUntil:      time.Now().Add(s.certMaxTTL),
		KeyID:           claims.SessionID.String(),
	})
	if err != nil {
		return SetupResult{}, fmt.Errorf("issue credential: %w", err)
	}
	res := SetupResult{
		TargetAddress:      targetAddress,
		CredentialKind:     cred.Kind,
		SessionID:          claims.SessionID.String(),
		RecordingRequired:  recordingRequired,
		RecordingObjectKey: recordingKey,
		// The host-key pin travels to the worker, which enforces it on the target
		// hop (fail closed on mismatch). Empty when the asset has no pin configured.
		TargetHostKey:   targetHostKey,
		TargetServerCA:  targetServerCA,
		DefaultDatabase: defaultDB,
		GrantID:         grantIDString(grantID),
	}
	switch cred.Kind {
	case "ssh-cert":
		res.SSHCertificate = cred.SSHCertificate
	case "ssh-password":
		res.Password = string(cred.Secret)
	case "ssh-key":
		res.PrivateKey = cred.Secret
	case "x509":
		res.X509Certificate = cred.X509Cert
		res.X509PrivateKey = cred.X509Key
	case "pg-password":
		res.Password = string(cred.Secret)
	default:
		return SetupResult{}, fmt.Errorf("unexpected credential kind %q", cred.Kind)
	}
	return res, nil
}

// grantIDString renders a pgtype.UUID as its string form, empty when NULL/invalid.
func grantIDString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

// containsLogin reports whether xs contains s.
func containsLogin(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// parseSSHPublicKey accepts authorized_keys text or raw wire form (copy of the
// broker's helper).
func parseSSHPublicKey(raw []byte) (ssh.PublicKey, error) {
	if pub, _, _, _, err := ssh.ParseAuthorizedKey(raw); err == nil {
		return pub, nil
	}
	return ssh.ParsePublicKey(raw)
}
