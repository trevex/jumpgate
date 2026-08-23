package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// folderPathIDs returns the ltree path text of one folder. Propagates
// pgx.ErrNoRows for a missing folder (callers decide how to treat "no folder").
func (s *sqlAuthorizer) folderPathIDs(ctx context.Context, id uuid.UUID) (string, error) {
	var p string
	if err := s.pool.QueryRow(ctx, `SELECT path_ids::text FROM folders WHERE id = $1`, id).Scan(&p); err != nil {
		return "", err
	}
	return p, nil
}

// folderSubtreeIDs returns every folder id in the subtrees rooted at `roots`
// (inclusive), using the GiST-indexed ltree descendant operator (<@). This
// replaces the recursive CTE down-walk; production callers use this version
// while the recursive variant is retained only for differential testing.
func (s *sqlAuthorizer) folderSubtreeIDs(ctx context.Context, roots []uuid.UUID) ([]uuid.UUID, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT f.id FROM folders f
WHERE f.path_ids <@ ANY (SELECT path_ids FROM folders WHERE id = ANY($1::uuid[]))`, roots)
	if err != nil {
		return nil, fmt.Errorf("folder subtree (ltree): %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}

// folderAncestorsAndSelf returns every ancestor-or-self folder id of id, using
// the ltree ancestor operator (@>). This replaces the recursive CTE up-walk;
// production callers use this version while the recursive variant is retained
// only for differential testing.
func (s *sqlAuthorizer) folderAncestorsAndSelf(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
SELECT f.id FROM folders f
WHERE f.path_ids @> (SELECT path_ids FROM folders WHERE id = $1)`, id)
	if err != nil {
		return nil, fmt.Errorf("folder ancestors (ltree): %w", err)
	}
	defer rows.Close()
	return scanUUIDs(rows)
}
