package rpc

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
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

// groupNotFoundOrInternal maps pgx.ErrNoRows to NotFound and anything else to Internal.
func groupNotFoundOrInternal(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return connect.NewError(connect.CodeNotFound, errors.New("group not found"))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// uuidFromPg converts a valid pgtype.UUID to a uuid.UUID.
func uuidFromPg(u pgtype.UUID) uuid.UUID { return u.Bytes }

// roleRefs resolves role ids to {id, name, folder_path}, computing each distinct
// scoped folder's path once. Preserves the input order.
func roleRefs(ctx context.Context, q *gen.Queries, ids []uuid.UUID) ([]*catalogv1.RoleRef, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.ListRolesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	pathByFolder := map[uuid.UUID]string{}
	refByID := map[uuid.UUID]*catalogv1.RoleRef{}
	for _, r := range rows {
		ref := &catalogv1.RoleRef{Id: r.ID.String(), Name: r.Name}
		if r.FolderID.Valid {
			fid := uuid.UUID(r.FolderID.Bytes)
			p, ok := pathByFolder[fid]
			if !ok {
				if p, err = q.FolderPath(ctx, fid); err != nil {
					return nil, err
				}
				pathByFolder[fid] = p
			}
			ref.FolderPath = p
		}
		refByID[r.ID] = ref
	}
	out := make([]*catalogv1.RoleRef, 0, len(ids))
	for _, id := range ids {
		if ref, ok := refByID[id]; ok {
			out = append(out, ref)
		}
	}
	return out, nil
}
