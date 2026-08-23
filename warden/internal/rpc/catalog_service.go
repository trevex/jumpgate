package rpc

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

// PostgreSQL SQLSTATE codes used to map DB constraint failures to Connect codes.
const (
	pgerrcodeUniqueViolation     = "23505"
	pgerrcodeForeignKeyViolation = "23503"
	pgerrcodeCheckViolation      = "23514"
)

// mapWriteErr maps a Postgres write error to an appropriate Connect code so that
// bad client input (a reference to a non-existent role/scope/subject, a violated
// constraint) surfaces as InvalidArgument/AlreadyExists rather than Internal.
// Returns nil for a nil error.
func mapWriteErr(err error) error {
	if err == nil {
		return nil
	}
	// A pre-mapped Connect error (e.g. an InvalidArgument from login validation)
	// passes through unchanged rather than being masked as Internal.
	if _, ok := err.(*connect.Error); ok {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcodeUniqueViolation:
			return connect.NewError(connect.CodeAlreadyExists, errors.New("already exists"))
		case pgerrcodeForeignKeyViolation:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("references a non-existent entity"))
		case pgerrcodeCheckViolation:
			return connect.NewError(connect.CodeInvalidArgument, errors.New("violates a constraint"))
		}
	}
	return connect.NewError(connect.CodeInternal, err)
}

// CatalogServer implements catalogv1connect.CatalogServiceHandler: folders,
// assets, and the caller's visible-asset catalog. Authorization config lives in
// AccessService.
type CatalogServer struct {
	capGuard
	q          *gen.Queries
	pool       *pgxpool.Pool
	authorizer authz.Authorizer
	reqReads   requestReadAuthorizer
	sealer     *secrets.Sealer
	terminator assetTerminator // wired in a later task; nil for now
}

// assetTerminator signals live-session teardown for an asset's sessions. Backed by
// *dataplane.Terminator; a nil terminator disables teardown.
type assetTerminator interface {
	TerminateAssetSessions(ctx context.Context, assetID uuid.UUID) error
}

// NewCatalogServer constructs the CatalogService implementation. pool is used to
// run CreateAsset + its inline config as one transaction. reqReads authorizes the
// request-party path of GetAssetDisplay; a nil reqReads disables that path (only
// the capability check can then grant a display read). sealer seals inline SSH
// login secrets during onboarding; a nil sealer fails those write paths closed.
func NewCatalogServer(q *gen.Queries, pool *pgxpool.Pool, authorizer authz.Authorizer, reqReads requestReadAuthorizer, sealer *secrets.Sealer, terminator assetTerminator) *CatalogServer {
	return &CatalogServer{capGuard: capGuard{authz: authorizer, q: q}, q: q, pool: pool, authorizer: authorizer, reqReads: reqReads, sealer: sealer, terminator: terminator}
}

func pgUUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func toFolderMsg(f gen.Folder) *catalogv1.Folder {
	return &catalogv1.Folder{Id: f.ID.String(), Name: f.Name, ParentId: pgUUIDToString(f.ParentID)}
}

func toAssetMsg(a gen.Asset) *catalogv1.Asset {
	return &catalogv1.Asset{Id: a.ID.String(), FolderId: a.FolderID.String(), Name: a.Name, Kind: a.Kind}
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

// optUUID parses a possibly-empty UUID string. Empty → (pgtype.UUID{}, false, nil).
func optUUID(s string) (pgtype.UUID, bool, error) {
	if s == "" {
		return pgtype.UUID{}, false, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, false, err
	}
	return pgUUID(id), true, nil
}

// notFoundOrInternal maps pgx.ErrNoRows to NotFound (existence hiding) and any other
// error to Internal.
func notFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such asset"))
	}
	return connect.NewError(connect.CodeInternal, err)
}
