package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestLtreeMatchesRecursive builds a randomly-structured tree (fanout=3,
// depth=4, yielding up to 120 nodes) and asserts that the ltree-backed subtree
// and ancestor queries return the SAME id sets as the recursive CTE walks for
// every node in the tree.
func TestLtreeMatchesRecursive(t *testing.T) {
	pool := newPool(t)
	s := &sqlAuthorizer{pool: pool}
	ctx := context.Background()

	ids := insertTree(t, pool, 3, 4)
	if len(ids) == 0 {
		t.Fatal("insertTree returned no ids")
	}

	for _, id := range ids {
		wantSub, err := s.folderSubtreeIDsRecursive(ctx, []uuid.UUID{id})
		mustNoErr(t, err)
		gotSub, err := s.folderSubtreeIDs(ctx, []uuid.UUID{id})
		mustNoErr(t, err)
		requireSameSet(t, wantSub, gotSub, "subtree(%s)", id)

		wantAnc, err := s.folderAncestorsAndSelfRecursive(ctx, id)
		mustNoErr(t, err)
		gotAnc, err := s.folderAncestorsAndSelf(ctx, id)
		mustNoErr(t, err)
		requireSameSet(t, wantAnc, gotAnc, "ancestors(%s)", id)
	}
}

// TestLtreeMoveRewritesSubtree verifies that:
//  1. Moving a folder (updating parent_id) rewrites path_ids for the entire
//     subtree — the moved node and its descendants appear under the new parent
//     and are absent from the old parent's subtree.
//  2. Renaming a folder (updating name) does NOT change path_ids, since
//     path_ids is built from UUIDs, not names.
func TestLtreeMoveRewritesSubtree(t *testing.T) {
	pool := newPool(t)
	s := &sqlAuthorizer{pool: pool}
	ctx := context.Background()

	// Tree: a → b → c; d is a separate root.
	a := mkFolder(t, pool, nil, "a")
	b := mkFolder(t, pool, &a, "b")
	c := mkFolder(t, pool, &b, "c")
	d := mkFolder(t, pool, nil, "d")

	// Move b (and its descendant c) under d.
	_, err := pool.Exec(ctx, `UPDATE folders SET parent_id = $1 WHERE id = $2`, d, b)
	mustNoErr(t, err)

	// d's subtree must now include b and c.
	subD, err := s.folderSubtreeIDs(ctx, []uuid.UUID{d})
	mustNoErr(t, err)
	requireContains(t, subD, b)
	requireContains(t, subD, c)

	// a's subtree must no longer include b or c.
	subA, err := s.folderSubtreeIDs(ctx, []uuid.UUID{a})
	mustNoErr(t, err)
	requireNotContains(t, subA, b)
	requireNotContains(t, subA, c)

	// Renaming b must leave path_ids unchanged.
	before, err := s.folderPathIDs(ctx, b)
	mustNoErr(t, err)
	_, err = pool.Exec(ctx, `UPDATE folders SET name = 'b2' WHERE id = $1`, b)
	mustNoErr(t, err)
	after, err := s.folderPathIDs(ctx, b)
	mustNoErr(t, err)
	if before != after {
		t.Fatalf("rename changed path_ids: %s -> %s", before, after)
	}
}
