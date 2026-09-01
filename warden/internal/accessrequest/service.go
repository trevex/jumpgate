// Package accessrequest implements the JIT access-request workflow: request a
// role on an asset, approve/deny/cancel a pending request, and mint time-boxed
// access_grants when a request reaches its required-approval threshold.
//
// CONCURRENCY: state transitions take a row lock on the access_request
// (GetAccessRequestForUpdate, FOR UPDATE) and count approvals inside the same
// tx, so two concurrent approvals cannot both cross the threshold and mint two
// grants. UNIQUE(request_id) on access_grants is the backstop; UNIQUE(request_id,
// approver_user_id) blocks double-voting.
//
// AUDIT: audit events are enqueued into the audit_outbox WITHIN the domain tx
// via audit.Logger.Enqueue (a plain insert on the caller's tx-bound querier), so
// each event becomes durable ATOMICALLY with the state change it records — either
// both commit or neither does. An enqueue failure rolls back the domain action
// (the RPC fails), because a durable action with no audit entry is not acceptable.
// A background drainer (audit.Logger.RunDrainer/DrainOnce) later moves outbox rows
// into the hash-linked, tamper-evident audit_log in seq order. Terminator
// notification (live-session teardown) stays POST-COMMIT: it must not fire for a
// change that then rolls back.
package accessrequest

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// pgUniqueViolation is the SQLSTATE for a unique-constraint violation.
const pgUniqueViolation = "23505"

// Sentinel errors the RPC handler maps to Connect codes.
var (
	ErrNotEligible         = errors.New("not eligible to request this role")               // → NotFound (existence-hiding)
	ErrNotRequestable      = errors.New("role is not JIT-requestable on asset")            // → FailedPrecondition
	ErrAlreadyActive       = errors.New("role already active on asset")                    // → FailedPrecondition
	ErrDuplicatePending    = errors.New("a pending request already exists")                // → AlreadyExists
	ErrNotPending          = errors.New("request is not pending")                          // → FailedPrecondition
	ErrNotApprover         = errors.New("not an approver for this request")                // → PermissionDenied
	ErrRequesterIneligible = errors.New("requester is no longer eligible for this access") // → FailedPrecondition
	ErrSelfApprove         = errors.New("cannot approve your own request")                 // → PermissionDenied
	ErrAlreadyVoted        = errors.New("already voted on this request")                   // → AlreadyExists
	ErrNotRequester        = errors.New("not the requester")                               // → PermissionDenied
	ErrGrantNotFound       = errors.New("grant not found")                                 // → NotFound
	ErrRevokeForbidden     = errors.New("not permitted to revoke this grant")              // → PermissionDenied
	ErrGrantInactive       = errors.New("grant is already inactive")                       // → FailedPrecondition
)

// Request is the DTO returned to the transport layer.
type Request struct {
	ID                uuid.UUID
	RequesterID       uuid.UUID
	RoleID            uuid.UUID
	AssetID           uuid.UUID
	Status            string
	RequiredApprovals int
	ApprovalsSoFar    int
	Reason            string
	CreatedAt         time.Time
	ResolvedAt        time.Time // zero when unresolved
	GrantID           uuid.UUID // uuid.Nil when no grant minted
}

// Grant is the DTO for an access_grant returned to the transport layer.
type Grant struct {
	ID            uuid.UUID
	RoleID        uuid.UUID
	AssetID       uuid.UUID
	SubjectUserID uuid.UUID
	GrantedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     time.Time // zero when not revoked
	RevokedReason string
	Active        bool // revoked_at IS NULL AND expires_at > now()
}

// Service is the JIT access-request domain service.
type Service struct {
	pool       *pgxpool.Pool
	q          *sqlc.Queries
	audit      *audit.Logger
	resolver   *approvals.Resolver
	roles      *authz.RoleResolver
	terminator GrantTerminator
	maxTTL     time.Duration
}

// NewService constructs the access-request Service. A nil terminator defaults to
// NoopTerminator; production wires the real dataplane.Terminator, which tears down
// live sessions on revocation via closure re-eval + LISTEN/NOTIFY.
func NewService(pool *pgxpool.Pool, auditLog *audit.Logger, resolver *approvals.Resolver, roles *authz.RoleResolver, terminator GrantTerminator, maxTTL time.Duration) *Service {
	if maxTTL <= 0 {
		maxTTL = 8 * time.Hour
	}
	if terminator == nil {
		terminator = NoopTerminator{}
	}
	return &Service{pool: pool, q: sqlc.New(pool), audit: auditLog, resolver: resolver, roles: roles, terminator: terminator, maxTTL: maxTTL}
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}
