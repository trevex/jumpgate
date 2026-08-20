package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// resolveFolderIDByPath walks a DNS-style leaf->root folder path (e.g. "db.prod")
// to a folder id, matching root->leaf. Returns pgx.ErrNoRows if any segment is
// missing so callers can map it to NotFound.
func resolveFolderIDByPath(ctx context.Context, q *gen.Queries, path string) (uuid.UUID, error) {
	segs := strings.Split(path, ".")
	var parent pgtype.UUID // NULL = top level
	var folderID uuid.UUID
	for i := len(segs) - 1; i >= 0; i-- {
		f, err := q.FolderByParentName(ctx, gen.FolderByParentNameParams{ParentID: parent, Name: segs[i]})
		if err != nil {
			return uuid.Nil, err
		}
		folderID = f.ID
		parent = pgUUID(f.ID)
	}
	return folderID, nil
}

// roleNotFoundOrInternal maps pgx.ErrNoRows to NotFound and anything else to Internal.
func roleNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such role"))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// uuidFromPg converts a valid pgtype.UUID to a uuid.UUID.
func uuidFromPg(u pgtype.UUID) uuid.UUID { return u.Bytes }
