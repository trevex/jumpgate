package dataplane

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// Terminator is the real GrantTerminator: it re-evaluates the connect predicate for
// the sessions a revoked/expired grant might have authorized and tears down only
// those that no longer pass. A session that still has a standing login survives.
type Terminator struct {
	pool  *pgxpool.Pool
	authz authz.Authorizer
	audit *audit.Logger
}

// NewTerminator builds the terminator.
func NewTerminator(pool *pgxpool.Pool, a authz.Authorizer, log *audit.Logger) *Terminator {
	return &Terminator{pool: pool, authz: a, audit: log}
}

// TerminateGrant satisfies accessrequest.GrantTerminator. It re-evaluates the
// (subject, asset) of the (now-revoked/expired) grant and tears down any of that
// pair's live sessions that no longer pass the connect predicate.
func (t *Terminator) TerminateGrant(ctx context.Context, grantID uuid.UUID) error {
	g, err := gen.New(t.pool).GetGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return t.Reevaluate(ctx, g.SubjectUserID, g.ScopeAssetID)
}

// Reevaluate re-checks the connect predicate for all live sessions of (user,asset)
// and tears down those that no longer pass. Exported so worker reconnect re-sync and
// the periodic eligibility sweep can reuse it. Idempotent: safe to call repeatedly —
// teardown of an already-terminating session is a no-op (see requestTeardown).
func (t *Terminator) Reevaluate(ctx context.Context, userID, assetID uuid.UUID) error {
	q := gen.New(t.pool)
	sessions, err := q.ListLiveSessionsByUserAsset(ctx, gen.ListLiveSessionsByUserAssetParams{UserID: userID, AssetID: assetID})
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		return nil
	}
	cfg, err := q.GetSSHAssetConfig(ctx, assetID)
	if err != nil {
		return err
	}
	logins, err := authz.EntitledLogins(ctx, t.authz, userID, assetID, cfg.AllowedLogins)
	if err != nil {
		return err
	}
	if len(logins) > 0 {
		return nil // still authorized; keep every session
	}
	for _, sess := range sessions {
		if err := t.requestTeardown(ctx, sess.ID, "authorization revoked"); err != nil {
			return err
		}
	}
	return nil
}

// MarkEnded records a session's end: it deletes the live_sessions row and enqueues
// a session.ended audit event, in one tx. Idempotent — if the row is already gone
// (deleted 0 rows), it is a clean no-op (no duplicate audit). Used by the reconnect
// re-sync (a worker that no longer has a session) and by SessionEnded reports.
func (t *Terminator) MarkEnded(ctx context.Context, sessionID uuid.UUID, reason string) error {
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := gen.New(tx)
	n, err := q.DeleteLiveSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil // already ended — no duplicate audit
	}
	detail, _ := json.Marshal(map[string]any{"session_id": sessionID.String(), "reason": reason})
	if err := t.audit.Enqueue(ctx, q, audit.Event{
		Type:    EventSessionEnded,
		ActorID: uuid.Nil,
		Subject: "live_session:" + sessionID.String(),
		Details: detail,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// requestTeardown marks a session terminating (once) and (re-)delivers the teardown
// signal. MarkLiveSessionTerminating flips a NULL terminate_requested_at and returns
// 0 rows thereafter, so the session.terminated audit event is recorded exactly once.
// The teardown notification is sent on every call so a lost delivery self-heals —
// telling an already-closing session to close is a no-op for the worker.
func (t *Terminator) requestTeardown(ctx context.Context, sessionID uuid.UUID, reason string) error {
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := gen.New(tx)
	n, err := q.MarkLiveSessionTerminating(ctx, sessionID)
	if err != nil {
		return err
	}
	if n > 0 {
		detail, _ := json.Marshal(map[string]any{"session_id": sessionID.String(), "reason": reason})
		if err := t.audit.Enqueue(ctx, q, audit.Event{
			Type:    EventSessionTerminated,
			ActorID: uuid.Nil,
			Subject: "live_session:" + sessionID.String(),
			Details: detail,
		}); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	// Re-deliver every time so a dropped notification self-heals.
	return NotifyTeardown(ctx, t.pool, sessionID.String(), reason)
}
