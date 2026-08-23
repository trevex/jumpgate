package authz

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mkFolder inserts a folder with the given name and optional parent, returning
// its id. The DB trigger populates path_ids automatically.
func mkFolder(t testing.TB, pool *pgxpool.Pool, parent *uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var err error
	if parent == nil {
		err = pool.QueryRow(context.Background(),
			`INSERT INTO folders(name) VALUES($1) RETURNING id`, name).Scan(&id)
	} else {
		err = pool.QueryRow(context.Background(),
			`INSERT INTO folders(name, parent_id) VALUES($1, $2) RETURNING id`, name, *parent).Scan(&id)
	}
	if err != nil {
		t.Fatalf("mkFolder(%s): %v", name, err)
	}
	return id
}

// insertTree builds a complete k-ary tree of the given fanout and depth,
// returning all created folder ids. depth=0 produces a single root node.
func insertTree(t testing.TB, pool *pgxpool.Pool, fanout, depth int) []uuid.UUID {
	t.Helper()
	var all []uuid.UUID
	var grow func(parent *uuid.UUID, level int)
	grow = func(parent *uuid.UUID, level int) {
		if level > depth {
			return
		}
		for i := 0; i < fanout; i++ {
			label := fmt.Sprintf("n-d%d-f%d", level, i)
			id := mkFolder(t, pool, parent, label)
			all = append(all, id)
			grow(&id, level+1)
		}
	}
	grow(nil, 0)
	return all
}

// requireSameSet asserts that a and b contain the same uuid.UUID values
// (order-independent). msgf/args are passed to t.Fatalf on mismatch.
func requireSameSet(t testing.TB, a, b []uuid.UUID, msgf string, args ...any) {
	t.Helper()
	norm := func(xs []uuid.UUID) []string {
		ss := make([]string, len(xs))
		for i, x := range xs {
			ss[i] = x.String()
		}
		sort.Strings(ss)
		return ss
	}
	na, nb := norm(a), norm(b)
	match := len(na) == len(nb)
	if match {
		for i := range na {
			if na[i] != nb[i] {
				match = false
				break
			}
		}
	}
	if !match {
		prefix := fmt.Sprintf(msgf, args...)
		t.Fatalf("%s: sets differ\n  got  %v\n  want %v", prefix, nb, na)
	}
}

// requireContains asserts that ids contains target.
func requireContains(t testing.TB, ids []uuid.UUID, target uuid.UUID) {
	t.Helper()
	for _, id := range ids {
		if id == target {
			return
		}
	}
	t.Fatalf("expected %s in %v", target, ids)
}

// requireNotContains asserts that ids does NOT contain target.
func requireNotContains(t testing.TB, ids []uuid.UUID, target uuid.UUID) {
	t.Helper()
	for _, id := range ids {
		if id == target {
			t.Fatalf("expected %s NOT in %v", target, ids)
		}
	}
}

// mustNoErr fails the test immediately if err is non-nil.
func mustNoErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
