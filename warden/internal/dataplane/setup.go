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
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

// Sentinel errors returned by Setup; the RPC layer maps them to Connect codes.
var (
	ErrBadToken      = errors.New("invalid session token")
	ErrKeyMismatch   = errors.New("client key does not match token binding")
	ErrNotAuthorized = errors.New("no login entitlement on asset")
	ErrReplay        = errors.New("session already set up")
	ErrNoTarget      = errors.New("asset has no target address")
	// ErrNoPreparedSession means IssueSessionCredential named a session id with no
	// live_sessions row (never prepared, already ended, or already aborted).
	ErrNoPreparedSession = errors.New("no prepared session for id")
	// ErrWrongWorker means the worker asking to issue a credential does not own the
	// prepared session (its worker_id differs from the recorded one).
	ErrWrongWorker = errors.New("worker does not own prepared session")
	// ErrIdentityUnverified means warden cannot verify a target-identity match on
	// the enforced path (e.g. no *targetidentity.Service wired).
	ErrIdentityUnverified = errors.New("target identity verification unavailable")
)

// credentialIssuer is the single mint seam the setup path depends on. *vault.Broker
// satisfies it; tests substitute a spy to prove the broker is never touched during
// preparation or on an identity mismatch. Kept in the consumer package on purpose.
type credentialIssuer interface {
	Issue(ctx context.Context, userID, assetID uuid.UUID, req vault.IssueRequest) (vault.Credential, error)
}

// SetupService redeems session tokens and records live sessions.
type SetupService struct {
	pool       *pgxpool.Pool
	verifier   *sessiontoken.Verifier
	authz      *authz.Authorizer
	broker     credentialIssuer
	identity   *targetidentity.Service // issue-time target-identity re-verification; nil disables the enforced path
	audit      *audit.Logger
	certMaxTTL time.Duration
}

// NewSetupService builds the session-setup service. identity backs the enforced
// two-phase flow (PrepareSession + IssueSessionCredential); it may be nil, which
// leaves only the migration-window SetupSession compat path usable.
func NewSetupService(pool *pgxpool.Pool, v *sessiontoken.Verifier, a *authz.Authorizer, b credentialIssuer, identity *targetidentity.Service, log *audit.Logger, certMaxTTL time.Duration) *SetupService {
	return &SetupService{pool: pool, verifier: v, authz: a, broker: b, identity: identity, audit: log, certMaxTTL: certMaxTTL}
}

// SetupResult is the successful outcome. The credential is discriminated by
// CredentialKind ("ssh-cert" | "ssh-password" | "ssh-key" | "x509" |
// "pg-password" | "rdp-password"); exactly one of the credential fields is
// populated.
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
	Login           string // the DB role warden authorized (the worker connects as this)
}

// capRecordExempt, when held on the asset, permits an unrecorded SSH session.
const capRecordExempt = "ssh:record:exempt"

// recordingObjectKey is the date-partitioned object key for a session recording.
// The protocol segment keeps one bucket usable across protocols; ext is the
// object extension ("cast" for asciicast, "ndjson" for the pgwire timeline).
func recordingObjectKey(sessionID uuid.UUID, at time.Time, protocol, ext string) string {
	u := at.UTC()
	return fmt.Sprintf("recordings/%s/%04d/%02d/%02d/%s.%s", protocol, u.Year(), u.Month(), u.Day(), sessionID.String(), ext)
}

// sessionPrep is the credential-free result of resolving a session token: the
// verified claims, the authorized login, and the per-protocol endpoint + policy.
// It carries everything the two-phase flow needs EXCEPT any credential.
type sessionPrep struct {
	claims            sessiontoken.Claims
	login             string
	protocol          string
	targetAddress     string
	targetHostKey     string
	targetServerCA    string
	defaultDB         string
	recordingRequired bool
	recordingKey      string
}

// resolveSession verifies the token, enforces the cnf binding (CLI) or reads the
// ticket-bound login (web), re-checks authorization against the live held-closure,
// and resolves the per-protocol endpoint + recording policy. It records NOTHING
// and issues NOTHING — it is the shared front half of both the compat SetupSession
// and the enforced PrepareSession.
func (s *SetupService) resolveSession(ctx context.Context, rawToken, login string, clientPub []byte) (sessionPrep, error) {
	claims, err := s.verifier.Verify(rawToken)
	if err != nil {
		return sessionPrep{}, ErrBadToken
	}
	// Web tickets carry no client key: the browser has no SSH key to prove, and the
	// login is bound in the token (authoritative — the ticket-mint already checked
	// the login entitlement). So the cnf/Kc proof is skipped and the request's
	// client key + login are ignored in favor of the claim. cnf-bearing (CLI)
	// tokens keep the client-key proof and honor the request's login.
	if claims.Mode == "web" {
		login = claims.Login
	} else {
		pub, err := parseSSHPublicKey(clientPub)
		if err != nil {
			return sessionPrep{}, ErrBadToken
		}
		if ssh.FingerprintSHA256(pub) != claims.ClientKeyFingerprint {
			return sessionPrep{}, ErrKeyMismatch
		}
	}
	q0 := sqlc.New(s.pool)
	// Fetch the user's data-plane capability set for the asset ONCE and derive BOTH
	// the login entitlement and the record-exemption from it (defense in depth over
	// the admission token). ConnectCapabilities matches the CreateSession mint.
	caps, err := authz.ConnectCapabilities(ctx, s.authz, claims.UserID, claims.AssetID)
	if err != nil {
		return sessionPrep{}, err
	}

	prep := sessionPrep{claims: claims, login: login, protocol: claims.Protocol}
	var allowed []string
	switch claims.Protocol {
	case "postgres":
		cfg, err := q0.GetPostgresAssetConfig(ctx, claims.AssetID)
		if err != nil {
			return sessionPrep{}, fmt.Errorf("get postgres asset config: %w", err)
		}
		if cfg.TargetAddress == "" {
			return sessionPrep{}, ErrNoTarget
		}
		prep.targetAddress, prep.targetServerCA, prep.defaultDB = cfg.TargetAddress, cfg.TargetServerCa, cfg.DefaultDatabase
		rows, err := q0.ListPostgresAssetLogins(ctx, claims.AssetID)
		if err != nil {
			return sessionPrep{}, fmt.Errorf("list postgres asset logins: %w", err)
		}
		for _, r := range rows {
			allowed = append(allowed, r.Role)
		}
		if !containsLogin(caps.EntitledLoginsFor(authz.DBLoginPrefix, allowed), login) {
			return sessionPrep{}, ErrNotAuthorized
		}
		prep.recordingRequired = true
		prep.recordingKey = recordingObjectKey(claims.SessionID, time.Now(), "postgres", "ndjson")
	case "rdp":
		cfg, err := q0.GetRDPAssetConfig(ctx, claims.AssetID)
		if err != nil {
			return sessionPrep{}, fmt.Errorf("get rdp asset config: %w", err)
		}
		if cfg.TargetAddress == "" {
			return sessionPrep{}, ErrNoTarget
		}
		prep.targetAddress, prep.targetServerCA = cfg.TargetAddress, cfg.TargetServerCa
		rows, err := q0.ListRDPAssetLogins(ctx, claims.AssetID)
		if err != nil {
			return sessionPrep{}, fmt.Errorf("list rdp asset logins: %w", err)
		}
		for _, r := range rows {
			allowed = append(allowed, r.Login)
		}
		if !containsLogin(caps.EntitledLoginsFor(authz.RDPLoginPrefix, allowed), login) {
			return sessionPrep{}, ErrNotAuthorized
		}
		prep.recordingRequired = true
		prep.recordingKey = recordingObjectKey(claims.SessionID, time.Now(), "rdp", "rdpg")
	default: // "ssh" (empty proto = legacy ssh)
		prep.protocol = "ssh"
		cfg, err := q0.GetSSHAssetConfig(ctx, claims.AssetID)
		if err != nil {
			return sessionPrep{}, fmt.Errorf("get ssh asset config: %w", err)
		}
		if cfg.TargetAddress == "" {
			return sessionPrep{}, ErrNoTarget
		}
		prep.targetAddress, prep.targetHostKey = cfg.TargetAddress, cfg.HostPublicKey
		rows, err := q0.ListSSHAssetLogins(ctx, claims.AssetID)
		if err != nil {
			return sessionPrep{}, fmt.Errorf("list ssh asset logins: %w", err)
		}
		for _, r := range rows {
			allowed = append(allowed, r.Login)
		}
		if !containsLogin(caps.EntitledLogins(allowed), login) {
			return sessionPrep{}, ErrNotAuthorized
		}
		prep.recordingRequired = !caps.Allows(capRecordExempt)
		prep.recordingKey = recordingObjectKey(claims.SessionID, time.Now(), "ssh", "cast")
	}
	return prep, nil
}

// recordLiveSession inserts the live_sessions row (PK = session JTI = replay guard)
// and enqueues eventType in the SAME tx, returning the resolved authorizing grant.
// It is the shared recording step of both SetupSession and PrepareSession.
func (s *SetupService) recordLiveSession(ctx context.Context, prep sessionPrep, workerID, eventType string) (pgtype.UUID, error) {
	claims := prep.claims
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	// Attribute the session to its authorizing JIT grant when exactly one active
	// grant covers (user, asset). Zero (standing) or multiple (ambiguous) → NULL.
	var grantID pgtype.UUID
	ids, err := q.ActiveGrantIDsForUserAsset(ctx, sqlc.ActiveGrantIDsForUserAssetParams{
		SubjectUserID: claims.UserID,
		ScopeAssetID:  claims.AssetID,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("resolve grant: %w", err)
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
		Protocol:    prep.protocol,
		Principals:  []string{prep.login},
		ClientKeyFp: claims.ClientKeyFingerprint,
	}); err != nil {
		if apierr.IsUniqueViolation(err) {
			return pgtype.UUID{}, ErrReplay
		}
		return pgtype.UUID{}, fmt.Errorf("insert live session: %w", err)
	}
	detail, _ := json.Marshal(map[string]any{
		"session_id": claims.SessionID.String(),
		"user_id":    claims.UserID.String(),
		"asset_id":   claims.AssetID.String(),
		"worker_id":  workerID,
		"login":      prep.login,
	})
	if err := s.audit.Enqueue(ctx, q, audit.Event{
		Type:    eventType,
		ActorID: claims.UserID,
		Subject: "live_session:" + claims.SessionID.String(),
		Details: detail,
	}); err != nil {
		return pgtype.UUID{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return pgtype.UUID{}, fmt.Errorf("commit: %w", err)
	}
	return grantID, nil
}

// issueInternal mints the target credential via the broker and fans it into an
// IssueResult. It performs NO identity verification — callers that enforce identity
// (IssueSessionCredential) MUST verify BEFORE calling this, so the broker is never
// reached on a mismatch.
//
// NOT dedup'd: the session id is passed as the broker KeyID, which is only an audit
// handle stamped into the SSH cert (vault.IssueRequest.KeyID), not a mint dedup key.
// So every call mints: for stored-secret kinds (ssh-password/pg-password/rdp-password)
// the returned bytes are the stable stored secret, while for minted kinds
// (ssh-cert/x509) each call is a re-verified re-mint — a FRESH short-TTL credential.
// That is safe because IssueCredential re-runs the full ownership + identity gate on
// every call and release stays scoped to the owning worker; it is NOT "exactly once".
func (s *SetupService) issueInternal(ctx context.Context, userID, assetID uuid.UUID, login, sessionID string, targetPub []byte) (IssueResult, error) {
	cred, err := s.broker.Issue(ctx, userID, assetID, vault.IssueRequest{
		Login:           login,
		ClientSSHPubKey: targetPub,
		ValidUntil:      time.Now().Add(s.certMaxTTL),
		KeyID:           sessionID,
	})
	if err != nil {
		return IssueResult{}, fmt.Errorf("issue credential: %w", err)
	}
	res := IssueResult{CredentialKind: cred.Kind, SessionID: sessionID, Login: login}
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
	case "rdp-password":
		// No dedicated proto oneof for rdp: the password rides the generic Password arm.
		res.Password = string(cred.Secret)
	default:
		return IssueResult{}, fmt.Errorf("unexpected credential kind %q", cred.Kind)
	}
	return res, nil
}

// Setup is the MIGRATION-WINDOW compat path (removed once every protocol slice
// enforces the two-phase PrepareSession + IssueSessionCredential flow). It
// preserves today's exact behavior: it resolves + records the session and issues
// the credential in one call, WITHOUT verifying the target's identity. Production
// ssh/postgres/rdp/k8s workers still call this until their vertical slice migrates.
// New enforcement lives in PrepareSession/IssueSessionCredential, not here.
func (s *SetupService) Setup(ctx context.Context, rawToken, workerID, login string, clientPub, targetPub []byte) (SetupResult, error) {
	prep, err := s.resolveSession(ctx, rawToken, login, clientPub)
	if err != nil {
		return SetupResult{}, err
	}
	// SSH certifies Kw for the target hop; reject a malformed worker key up front
	// (preserves the pre-refactor ErrBadToken behavior before any row is written).
	if prep.protocol == "ssh" {
		if _, err := parseSSHPublicKey(targetPub); err != nil {
			return SetupResult{}, ErrBadToken
		}
	}
	grantID, err := s.recordLiveSession(ctx, prep, workerID, EventSessionStarted)
	if err != nil {
		return SetupResult{}, err
	}
	// Cert issuance is POST-COMMIT: the session is already recorded, so a cert-issue
	// failure returns an error but leaves the recorded session in place.
	iss, err := s.issueInternal(ctx, prep.claims.UserID, prep.claims.AssetID, prep.login, prep.claims.SessionID.String(), targetPub)
	if err != nil {
		return SetupResult{}, err
	}
	return SetupResult{
		TargetAddress:      prep.targetAddress,
		CredentialKind:     iss.CredentialKind,
		SSHCertificate:     iss.SSHCertificate,
		Password:           iss.Password,
		PrivateKey:         iss.PrivateKey,
		SessionID:          prep.claims.SessionID.String(),
		RecordingRequired:  prep.recordingRequired,
		RecordingObjectKey: prep.recordingKey,
		TargetHostKey:      prep.targetHostKey,
		GrantID:            grantIDString(grantID),
		X509Certificate:    iss.X509Certificate,
		X509PrivateKey:     iss.X509PrivateKey,
		TargetServerCA:     prep.targetServerCA,
		DefaultDatabase:    prep.defaultDB,
		Login:              prep.login,
	}, nil
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
