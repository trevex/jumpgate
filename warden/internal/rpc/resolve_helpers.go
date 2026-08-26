package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// resolveParentFolderRef resolves an optional folder reference to its id.
// "" → uuid.Nil (root; always browsable, contents are visibility-filtered).
// A valid UUID string → GetFolder lookup (miss → NotFound).
// Else → resolveFolderIDByPath (miss → NotFound).
// No visibility gate is applied; the caller's list operation is itself
// visibility-filtered, so any authenticated user may name any folder (they will
// just get an empty result set if they have no visibility into it).
func resolveParentFolderRef(ctx context.Context, q *sqlc.Queries, ref string) (uuid.UUID, error) {
	if ref == "" {
		return uuid.Nil, nil
	}
	if id, err := uuid.Parse(ref); err == nil {
		if _, ferr := q.GetFolder(ctx, id); ferr != nil {
			return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
		}
		return id, nil
	}
	fid, err := resolveFolderIDByPath(ctx, q, ref)
	if err != nil {
		return uuid.Nil, connect.NewError(connect.CodeNotFound, errors.New("no such folder"))
	}
	return fid, nil
}

// resolveFolderIDByPath walks a DNS-style leaf->root folder path (e.g. "db.prod")
// to a folder id, matching root->leaf. Returns pgx.ErrNoRows if any segment is
// missing so callers can map it to NotFound.
func resolveFolderIDByPath(ctx context.Context, q *sqlc.Queries, path string) (uuid.UUID, error) {
	segs := strings.Split(path, ".")
	var parent pgtype.UUID // NULL = top level
	var folderID uuid.UUID
	for i := len(segs) - 1; i >= 0; i-- {
		f, err := q.FolderByParentName(ctx, sqlc.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
		if err != nil {
			return uuid.Nil, err
		}
		folderID = f.ID
		parent = pgUUID(f.ID)
	}
	return folderID, nil
}

// pgUUIDToString renders a nullable pgtype.UUID as a string ("" for NULL). Shared by
// the identity/access proto mappers.
func pgUUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
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
