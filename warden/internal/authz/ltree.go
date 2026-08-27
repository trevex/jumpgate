package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// folderPathIDs returns the ltree path text of one folder. Propagates
// pgx.ErrNoRows for a missing folder (callers decide how to treat "no folder").
func (az *Authorizer) folderPathIDs(ctx context.Context, id uuid.UUID) (string, error) {
	return az.queries().FolderPathIDs(ctx, id)
}

// folderSubtreeIDs returns every folder id in the subtrees rooted at `roots`
// (inclusive), using the GiST-indexed ltree descendant operator (<@). This
// replaces the recursive CTE down-walk; production callers use this version
// while the recursive variant is retained only for differential testing.
func (az *Authorizer) folderSubtreeIDs(ctx context.Context, roots []uuid.UUID) ([]uuid.UUID, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	ids, err := az.queries().FolderSubtreeIDsByRoots(ctx, roots)
	if err != nil {
		return nil, fmt.Errorf("folder subtree (ltree): %w", err)
	}
	return ids, nil
}

// folderAncestorsAndSelf returns every ancestor-or-self folder id of id, using
// the ltree ancestor operator (@>). This replaces the recursive CTE up-walk;
// production callers use this version while the recursive variant is retained
// only for differential testing.
func (az *Authorizer) folderAncestorsAndSelf(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	ids, err := az.queries().FolderAncestorsByPath(ctx, uuidArg(id))
	if err != nil {
		return nil, fmt.Errorf("folder ancestors (ltree): %w", err)
	}
	return ids, nil
}
