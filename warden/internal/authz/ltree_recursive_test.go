package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This file holds the recursive-CTE reference implementations of the folder
// subtree / ancestor walks. Production code resolves these through the
// ltree-backed folderSubtreeIDs / folderAncestorsAndSelf (ltree.go); these
// recursive variants exist ONLY as the differential-test oracle for
// TestLtreeMatchesRecursive, so they live in test code — the production packages
// must never hand-write closure/recursive SQL (enforced by
// TestNoRawClosureSQLInGo).

// folderSubtreeIDsRecursive returns every folder id in the subtrees rooted at
// `roots` (inclusive), via a single recursive down-walk (parent_id = ancestor.id).
func (s *Authorizer) folderSubtreeIDsRecursive(ctx context.Context, roots []uuid.UUID) ([]uuid.UUID, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE sub AS (
    SELECT id FROM folders WHERE id = ANY(@roots::uuid[])
  UNION
    SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id
)
SELECT id FROM sub`, pgx.NamedArgs{"roots": roots})
	if err != nil {
		return nil, fmt.Errorf("folder subtree: %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}

// folderAncestorsAndSelfRecursive returns every ancestor-or-self folder id of id,
// walking parent links up to the root via a recursive CTE.
func (s *Authorizer) folderAncestorsAndSelfRecursive(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
WITH RECURSIVE up AS (
    SELECT folders.id, folders.parent_id FROM folders WHERE folders.id = @id
    UNION ALL
    SELECT f.id, f.parent_id FROM folders f JOIN up ON f.id = up.parent_id
)
SELECT up.id FROM up`, pgx.NamedArgs{"id": id})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []uuid.UUID
	for rows.Next() {
		var fid uuid.UUID
		if err := rows.Scan(&fid); err != nil {
			return nil, err
		}
		items = append(items, fid)
	}
	return items, rows.Err()
}
