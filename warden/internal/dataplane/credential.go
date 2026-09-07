package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/targetidentity"
)

// This file holds the enforced two-phase session flow: PrepareSession returns the
// endpoint + trust anchors WITHOUT a credential, and IssueSessionCredential releases
// the credential only after warden re-verifies the worker's observed target identity
// against a current active anchor. The shared front-half steps (resolveSession,
// recordLiveSession, issueInternal) and the migration-window Setup compat shim live
// in setup.go because both paths use them.

// PrepareResult is the credential-free outcome of PrepareSession: the endpoint,
// policy, current endpoint revision, and the active trust anchors the worker must
// match before it may call IssueSessionCredential. It NEVER carries a credential.
type PrepareResult struct {
	SessionID          string
	EndpointRevision   int64
	TargetAddress      string
	RecordingRequired  bool
	RecordingObjectKey string
	TargetHostKey      string
	TargetServerCA     string
	DefaultDatabase    string
	GrantID            string
	Login              string
	Anchors            []targetidentity.SessionAnchor
}

// IssueResult is the credential-bearing outcome of IssueSessionCredential (and the
// internal issue step). Exactly one credential field is populated per CredentialKind.
type IssueResult struct {
	CredentialKind  string
	SSHCertificate  []byte
	Password        string
	PrivateKey      []byte
	X509Certificate []byte
	X509PrivateKey  []byte
	SessionID       string
	Login           string
}

// Prepare is the first phase of the enforced flow: it resolves + records the live
// session (session.prepared audit) and returns the endpoint, policy, current
// endpoint revision, and the asset's active trust anchors — but NEVER a credential.
// The worker then connects and authenticates the target itself before calling
// IssueSessionCredential.
func (s *SetupService) Prepare(ctx context.Context, rawToken, workerID, login string, clientPub []byte) (PrepareResult, error) {
	if s.identity == nil {
		return PrepareResult{}, ErrIdentityUnverified
	}
	prep, err := s.resolveSession(ctx, rawToken, login, clientPub)
	if err != nil {
		return PrepareResult{}, err
	}
	revision, anchors, err := s.identity.SessionAnchors(ctx, prep.claims.AssetID)
	if err != nil {
		return PrepareResult{}, fmt.Errorf("load session anchors: %w", err)
	}
	grantID, err := s.recordLiveSession(ctx, prep, workerID, EventSessionPrepared)
	if err != nil {
		return PrepareResult{}, err
	}
	return PrepareResult{
		SessionID:          prep.claims.SessionID.String(),
		EndpointRevision:   revision,
		TargetAddress:      prep.targetAddress,
		RecordingRequired:  prep.recordingRequired,
		RecordingObjectKey: prep.recordingKey,
		TargetHostKey:      prep.targetHostKey,
		TargetServerCA:     prep.targetServerCA,
		DefaultDatabase:    prep.defaultDB,
		GrantID:            grantIDString(grantID),
		Login:              prep.login,
		Anchors:            anchors,
	}, nil
}

// IssueCredential is the second phase: it releases the target credential for a
// prepared session, and ONLY after re-confirming the worker's observed target
// identity matches a current active anchor. The calling worker must own the
// prepared session and report the current endpoint revision. On ANY verification
// failure the broker is NOT called; the prepared session is aborted (row deleted +
// session.aborted audited) so a mismatched preparation leaves nothing behind.
func (s *SetupService) IssueCredential(ctx context.Context, sessionID, workerID string, reportedRevision int64, matchedAnchorID, observedFingerprint string, targetPub []byte) (IssueResult, error) {
	if s.identity == nil {
		return IssueResult{}, ErrIdentityUnverified
	}
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return IssueResult{}, ErrNoPreparedSession
	}
	row, err := sqlc.New(s.pool).GetLiveSession(ctx, sid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return IssueResult{}, ErrNoPreparedSession
		}
		return IssueResult{}, fmt.Errorf("load prepared session: %w", err)
	}
	// Ownership is checked BEFORE any verification or cleanup: a worker that does
	// not own the session must never be able to abort it or trigger a mint.
	if row.WorkerID != workerID {
		return IssueResult{}, ErrWrongWorker
	}
	anchorID, err := uuid.Parse(matchedAnchorID)
	if err != nil {
		s.abortSession(ctx, row, "invalid matched anchor id")
		return IssueResult{}, targetidentity.ErrIdentityMismatch
	}
	matched, verr := s.identity.VerifySessionTarget(ctx, targetidentity.VerifySessionTargetRequest{
		AssetID:             row.AssetID,
		ReportedRevision:    reportedRevision,
		AnchorID:            anchorID,
		ObservedFingerprint: observedFingerprint,
	})
	if verr != nil {
		// Broker is NOT reached. Abort the prepared session so a failed/mismatched
		// preparation is torn down rather than left dangling.
		s.abortSession(ctx, row, verr.Error())
		return IssueResult{}, verr
	}
	login := ""
	if len(row.Principals) > 0 {
		login = row.Principals[0]
	}
	// The identity is verified: record it (best-effort, post-fact, like the broker's
	// own credential.issued) then release the credential.
	detail, _ := json.Marshal(map[string]any{
		"session_id":  sessionID,
		"asset_id":    row.AssetID.String(),
		"worker_id":   workerID,
		"anchor_id":   matched.String(),
		"fingerprint": observedFingerprint,
		"revision":    reportedRevision,
	})
	if aerr := s.audit.Append(ctx, audit.Event{
		Type:    EventTargetIdentityVerified,
		ActorID: row.UserID,
		Subject: "live_session:" + sessionID,
		Details: detail,
	}); aerr != nil {
		slog.Error("audit append failed", "event", EventTargetIdentityVerified, "session_id", sessionID, "err", aerr)
	}
	return s.issueInternal(ctx, row.UserID, row.AssetID, login, sessionID, targetPub)
}

// abortSession tears down a prepared session that failed credential issuance:
// it deletes the live_sessions row and audits session.aborted in one tx. It is
// best-effort — a cleanup failure is logged, not returned, so it never masks the
// underlying verification error the caller is about to return.
func (s *SetupService) abortSession(ctx context.Context, row sqlc.LiveSession, reason string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		slog.Error("abort session begin failed", "session_id", row.ID.String(), "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.DeleteLiveSession(ctx, row.ID); err != nil {
		slog.Error("abort session delete failed", "session_id", row.ID.String(), "err", err)
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"session_id": row.ID.String(),
		"asset_id":   row.AssetID.String(),
		"worker_id":  row.WorkerID,
		"reason":     reason,
	})
	if err := s.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventSessionAborted,
		ActorID: row.UserID,
		Subject: "live_session:" + row.ID.String(),
		Details: detail,
	}); err != nil {
		slog.Error("abort session audit failed", "session_id", row.ID.String(), "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Error("abort session commit failed", "session_id", row.ID.String(), "err", err)
	}
}
