package authz

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxuuid "github.com/vgarvardt/pgx-google-uuid/v5"

	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/testsupport"
)

// queryCounter is a pgx.QueryTracer that counts round-trips: every Query,
// QueryRow, and Exec on a tracked connection fires TraceQueryStart exactly once,
// so the counter is the number of SQL round-trips issued while it is active.
type queryCounter struct{ n int64 }

func (c *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	atomic.AddInt64(&c.n, 1)
	return ctx
}

func (c *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *queryCounter) load() int64 { return atomic.LoadInt64(&c.n) }
func (c *queryCounter) reset()      { atomic.StoreInt64(&c.n, 0) }

// newCountingPool mirrors newPool (DSN from testsupport.StartPostgres, migrate.Up,
// the pgx-google-uuid AfterConnect registration) but additionally installs a
// queryCounter as the connection Tracer so every round-trip is counted. It returns
// the pool and the counter.
func newCountingPool(t *testing.T) (*pgxpool.Pool, *queryCounter) {
	t.Helper()
	dsn := testsupport.StartPostgres(t)
	if err := migrate.Up(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	counter := &queryCounter{}
	cfg.ConnConfig.Tracer = counter
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, counter
}

// seedBrowseTree builds `width` child folders under `parent` (for the folder
// browse) and `width` assets directly IN `parent` (for the asset browse — a
// non-cascade VisibleAssetsUnder considers only assets whose folder IS `parent`).
// Combined with a management binding on `parent`, a non-cascade browse of `parent`
// returns all `width` child folders and all `width` assets.
func seedBrowseTree(ctx context.Context, t *testing.T, q *sqlc.Queries, parent uuid.UUID, width int, prefix string) {
	t.Helper()
	for i := 0; i < width; i++ {
		if _, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{
			Name:     prefix + "-f" + itoa(i),
			ParentID: pgUUID(parent),
		}); err != nil {
			t.Fatalf("seedBrowseTree folder %d: %v", i, err)
		}
		if _, err := q.CreateAsset(ctx, sqlc.CreateAssetParams{
			FolderID: parent, Name: prefix + "-a" + itoa(i), Labels: []byte("{}"), Kind: "ssh",
		}); err != nil {
			t.Fatalf("seedBrowseTree asset %d: %v", i, err)
		}
	}
}

// itoa is a tiny base-10 formatter avoiding an strconv import for this test file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestBrowseQueryCountIsO1 is the query-count drift guard for the "authz set-based
// query rework" (slices B/C). The six catalog-browse methods were made set-based:
// a browse now issues a small CONSTANT number of SQL round-trips that does NOT grow
// with the number of folders/assets at the level being browsed. Before the rework a
// non-admin catalog browse ran an N+1 (~384 queries / ~5.8s, scaling with width).
//
// The test seeds two sibling subtrees of very different width (SMALL=3, LARGE=40)
// each under its own parent, a non-admin user with a folder-scoped
// catalog:folder:read + catalog:asset:read management binding on each parent (so
// every child folder and asset is visible), then runs the same browse against both
// parents and compares the round-trip counts.
//
//	(a) O(1) guard: count(SMALL) == count(LARGE) per method. A reintroduced N+1
//	    would make LARGE's count exceed SMALL's proportionally to width (37 more
//	    nodes), so this assertion is non-vacuous only because LARGE has many more
//	    nodes AND both browses return non-empty results (asserted below).
//
//	(b) absolute bound: each method's count <= a small constant. Measured on the
//	    set-based implementation (identical for SMALL and LARGE):
//	        VisibleFoldersUnder = 7
//	        VisibleAssetsUnder  = 3
//	        VisibleRolesUnder   = 3
//	        VisibleGroupsUnder  = 2
//	    Thresholds are measured+3 headroom. Pre-rework these scaled with width and
//	    ran ~384 for a modest tree.
func TestBrowseQueryCountIsO1(t *testing.T) {
	pool, counter := newCountingPool(t)
	ctx := context.Background()
	q := sqlc.New(pool)

	user, err := q.CreateUser(ctx, sqlc.CreateUserParams{Email: "browse@qc", DisplayName: "Browser"})
	if err != nil {
		t.Fatal(err)
	}

	// SMALL and LARGE subtrees, each under its own parent.
	smallParent, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "qc-small"})
	if err != nil {
		t.Fatal(err)
	}
	largeParent, err := q.CreateFolder(ctx, sqlc.CreateFolderParams{Name: "qc-large"})
	if err != nil {
		t.Fatal(err)
	}
	const (
		smallWidth = 3
		largeWidth = 40
	)
	seedBrowseTree(ctx, t, q, smallParent.ID, smallWidth, "s")
	seedBrowseTree(ctx, t, q, largeParent.ID, largeWidth, "l")

	// A folder-scoped management binding on each parent makes every child folder and
	// asset visible/governed to the non-admin user via the down-tree cascade.
	mgmtRole := createRoleWithCaps(t, ctx, q, "qc-mgmt", pgtype.UUID{},
		caps("catalog:folder:read", "catalog:asset:read", "access:role:read", "identity:group:read"))
	for _, parent := range []uuid.UUID{smallParent.ID, largeParent.ID} {
		if _, err := q.CreateRoleBinding(ctx, sqlc.CreateRoleBindingParams{
			RoleID: mgmtRole.ID, ScopeFolderID: pgUUID(parent), SubjectUserID: pgUUID(user.ID),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Home some roles and groups directly under each parent so the role/group browses
	// also return non-empty sets (access:role:read / identity:group:read on the
	// parent make folder-homed roles/groups visible via the same cascade).
	for i := 0; i < smallWidth; i++ {
		if _, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "s-role" + itoa(i), FolderID: pgUUID(smallParent.ID)}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "s-grp" + itoa(i), FolderID: pgUUID(smallParent.ID)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < largeWidth; i++ {
		if _, err := q.CreateRole(ctx, sqlc.CreateRoleParams{Name: "l-role" + itoa(i), FolderID: pgUUID(largeParent.ID)}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateGroup(ctx, sqlc.CreateGroupParams{Name: "l-grp" + itoa(i), FolderID: pgUUID(largeParent.ID)}); err != nil {
			t.Fatal(err)
		}
	}

	a := New(pool)

	// measure runs fn with the counter reset, returning the round-trip count.
	measure := func(fn func()) int64 {
		counter.reset()
		fn()
		return counter.load()
	}

	// Each browse is measured once against SMALL and once against LARGE. The result
	// sets are validated non-empty and width-sized so the O(1) comparison is
	// meaningful (a per-item N+1 could not stay flat across a 3→40 jump).
	type method struct {
		name  string
		bound int64 // absolute per-call ceiling (measured + ~3 headroom)
		run   func(parent uuid.UUID) int
	}
	methods := []method{
		{
			name: "VisibleFoldersUnder", bound: 10,
			run: func(parent uuid.UUID) int {
				fs, err := a.VisibleFoldersUnder(ctx, user.ID, parent, false)
				if err != nil {
					t.Fatal(err)
				}
				return len(fs)
			},
		},
		{
			name: "VisibleAssetsUnder", bound: 6,
			run: func(parent uuid.UUID) int {
				as, err := a.VisibleAssetsUnder(ctx, user.ID, parent, false)
				if err != nil {
					t.Fatal(err)
				}
				return len(as)
			},
		},
		{
			name: "VisibleRolesUnder", bound: 6,
			run: func(parent uuid.UUID) int {
				rs, err := a.VisibleRolesUnder(ctx, user.ID, parent, false)
				if err != nil {
					t.Fatal(err)
				}
				return len(rs)
			},
		},
		{
			name: "VisibleGroupsUnder", bound: 5,
			run: func(parent uuid.UUID) int {
				gs, err := a.VisibleGroupsUnder(ctx, user.ID, parent, false)
				if err != nil {
					t.Fatal(err)
				}
				return len(gs)
			},
		},
	}

	// Expected non-empty result sizes per method (folders/assets are direct children;
	// roles/groups are folder-homed).
	wantSmall := map[string]int{
		"VisibleFoldersUnder": smallWidth,
		"VisibleAssetsUnder":  smallWidth,
		"VisibleRolesUnder":   smallWidth,
		"VisibleGroupsUnder":  smallWidth,
	}
	wantLarge := map[string]int{
		"VisibleFoldersUnder": largeWidth,
		"VisibleAssetsUnder":  largeWidth,
		"VisibleRolesUnder":   largeWidth,
		"VisibleGroupsUnder":  largeWidth,
	}

	for _, m := range methods {
		m := m
		t.Run(m.name, func(t *testing.T) {
			var gotSmall, gotLarge int
			cntSmall := measure(func() { gotSmall = m.run(smallParent.ID) })
			cntLarge := measure(func() { gotLarge = m.run(largeParent.ID) })

			// Non-vacuity: both browses must return the full width-sized set, and
			// LARGE must be much larger than SMALL, or the O(1) comparison proves
			// nothing.
			if gotSmall != wantSmall[m.name] {
				t.Fatalf("%s SMALL returned %d results, want %d (browse must be non-empty)", m.name, gotSmall, wantSmall[m.name])
			}
			if gotLarge != wantLarge[m.name] {
				t.Fatalf("%s LARGE returned %d results, want %d (browse must be non-empty)", m.name, gotLarge, wantLarge[m.name])
			}
			if gotLarge <= gotSmall {
				t.Fatalf("%s: LARGE (%d) must return many more nodes than SMALL (%d) for the O(1) guard to be non-vacuous", m.name, gotLarge, gotSmall)
			}

			// (a) O(1) primary guard: the round-trip count must NOT scale with width.
			if cntSmall != cntLarge {
				t.Fatalf("%s: query count scales with tree width — N+1 regression!\n"+
					"  SMALL (%d nodes) = %d queries\n"+
					"  LARGE (%d nodes) = %d queries\n"+
					"  set-based browse must issue an equal, constant number of round-trips",
					m.name, gotSmall, cntSmall, gotLarge, cntLarge)
			}

			// (b) absolute bound: a per-call ceiling with modest headroom.
			if cntLarge > m.bound {
				t.Fatalf("%s: %d queries exceeds bound %d — investigate a residual N+1 "+
					"(pre-rework browse was ~384 and scaled with width)", m.name, cntLarge, m.bound)
			}

			t.Logf("%s: SMALL=%d LARGE=%d queries (bound %d); results SMALL=%d LARGE=%d",
				m.name, cntSmall, cntLarge, m.bound, gotSmall, gotLarge)
		})
	}
}
