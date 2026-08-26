// Package catalog owns the catalog domain vertical slice: folders, assets, the
// caller's visible-asset catalog, and asset SSH connection config. The Service
// carries the transactional/business logic (proto-free); the Handler adapts it to
// ConnectRPC. Authorization config (roles/bindings/policies) lives in the access
// domain; catalog only reads visibility from the authorizer.
package catalog

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apierr"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// sessionTerminator is the narrow dependency catalog needs from the data plane to
// tear down an asset's live sessions before the asset is deleted. Backed by
// *dataplane.Terminator; a nil terminator disables teardown.
type sessionTerminator interface {
	TerminateAssetSessions(ctx context.Context, assetID uuid.UUID) error
}

// requestReadAuthorizer authorizes display reads for callers who are party to a
// pending access request referencing the entity (the requester or a standing
// approver). It is additive to capability checks: consulted only after a capability
// check denies. Backed by *accessrequest.Service; a nil reqReads disables that path.
type requestReadAuthorizer interface {
	CanReadForRequest(ctx context.Context, caller uuid.UUID, kind accessrequest.ReqEntityKind, id uuid.UUID) (bool, error)
}

// Service is the catalog domain service. It owns the pool (for multi-step
// transactions), the sqlc queries, the sealer (inline SSH login secrets), the
// session terminator (pre-delete teardown), the authorizer (visibility), and the
// request-read authorizer (decision-context reads).
type Service struct {
	pool       *pgxpool.Pool
	q          *sqlc.Queries
	sealer     *secrets.Sealer
	terminator sessionTerminator
	authz      authz.Authorizer
	reqReads   requestReadAuthorizer
}

// NewService constructs the catalog Service over pool, building its own sqlc
// queries. sealer seals inline SSH login secrets during onboarding (a nil sealer
// fails those write paths closed); terminator tears down an asset's live sessions
// before DeleteAsset (a nil terminator disables teardown); reqReads authorizes the
// request-party path of GetAssetDisplay (a nil reqReads disables it).
func NewService(pool *pgxpool.Pool, sealer *secrets.Sealer, term sessionTerminator, a authz.Authorizer, rr requestReadAuthorizer) *Service {
	return &Service{pool: pool, q: sqlc.New(pool), sealer: sealer, terminator: term, authz: a, reqReads: rr}
}

// requireCap denies unless caller holds `capability` at `scope`. It mirrors
// apiguard.Guard.RequireCap so the entangled methods (whose cap/visibility checks
// interleave with DB work) can gate in place with identical behavior.
func (s *Service) requireCap(ctx context.Context, caller uuid.UUID, capability string, scope authz.Scope) error {
	caps, err := s.authz.CapabilitiesOnScope(ctx, caller, scope)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !caps.Allows(capability) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("missing capability %q", capability))
	}
	return nil
}

// ── small shared helpers (moved verbatim from rpc) ──────────────────────────────

// pgUUID wraps a uuid.UUID as a valid pgtype.UUID.
func pgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// mapWrite maps a Postgres write error to an appropriate Connect code (see
// apierr.MapWrite): bad-input constraint failures surface as
// InvalidArgument/AlreadyExists rather than Internal.
func mapWrite(err error) error { return apierr.MapWrite(err) }

// pgText maps "" to a NULL pgtype.Text, else a valid one.
func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// joinPath builds an asset's DNS-style path: the asset name (the leaf) followed by
// its folder's leaf->root path. folderPath is the containing folder's own leaf-first
// path (empty only defensively — a real asset always has a folder).
func joinPath(folderPath, name string) string {
	if folderPath == "" {
		return name
	}
	return name + "." + folderPath
}

// notFoundOrInternal maps pgx.ErrNoRows to NotFound (existence hiding) and any other
// error to Internal.
func notFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// folderNotFoundOrInternal maps pgx.ErrNoRows to NotFound and any other error to Internal.
func folderNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// ── domain result rows (proto-free; the handler maps these to proto) ─────────────

// AssetWithConfig is a single asset plus its computed DNS path and optional SSH
// config (nil cfg = the asset has no ssh config row).
type AssetWithConfig struct {
	Asset  sqlc.Asset
	Path   string
	Config *sqlc.SshAssetConfig
	Logins []sqlc.SshAssetLogin
}

// FolderResult is a single folder plus its computed DNS path.
type FolderResult struct {
	Folder sqlc.Folder
	Path   string
}

// AssetRow is a browse/list asset row with its computed DNS path.
type AssetRow struct {
	Asset sqlc.Asset
	Path  string
}

// FolderRow is a browse/list folder row with its computed DNS path and governance flag.
type FolderRow struct {
	Folder   sqlc.Folder
	Path     string
	Governed bool
}

// RoleRow is a browse role row with its capabilities and home-folder path.
type RoleRow struct {
	Role       sqlc.Role
	Caps       []string
	FolderPath string
}

// GroupRow is a browse group row with its home-folder path.
type GroupRow struct {
	Group      sqlc.Group
	FolderPath string
}

// RoleRef is a resolved role reference {id, name, folder_path}.
type RoleRef struct {
	ID         string
	Name       string
	FolderPath string
}

// AssetAccess is the caller's access to a single asset.
type AssetAccess struct {
	ActiveRoleIDs          []string
	RequestableRoleIDs     []string
	ActiveRoles            []RoleRef
	RequestableRoles       []RoleRef
	Capabilities           []string
	ManagementCapabilities []string
}

// SearchHit is a visibility-filtered catalog search result.
type SearchHit struct {
	Kind string
	ID   string
	Name string
	Path string
}

// ResolveResult is a resolved id + canonical DNS path.
type ResolveResult struct {
	ID   string
	Path string
}
