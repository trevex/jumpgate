//go:build bench

package bench

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// allTables lists every table the generator writes, truncated (RESTART IDENTITY
// CASCADE) at the start of each Generate so profiles never cross-contaminate.
var allTables = []string{
	"live_sessions", "worker_presence", "access_grants", "access_requests",
	"request_policy_subjects", "request_policies", "role_bindings", "role_grants",
	"role_capabilities", "roles", "group_memberships", "groups",
	"ssh_asset_login", "catalog_names", "assets", "folders", "users",
}

func truncateAll(ctx context.Context, tb testing.TB, pool *pgxpool.Pool) {
	tb.Helper()
	if _, err := pool.Exec(ctx, "TRUNCATE "+strings.Join(allTables, ", ")+" RESTART IDENTITY CASCADE"); err != nil {
		tb.Fatalf("truncate: %v", err)
	}
}

// Generate truncates the shared DB and seeds Profile p, returning reference
// handles. Seeding runs OUTSIDE the benchmark timer (callers reset the timer after).
func Generate(tb testing.TB, p Profile) *World {
	tb.Helper()
	pool, _ := sharedDB(tb)
	ctx := context.Background()
	truncateAll(ctx, tb, pool)

	w := &World{RootParent: uuid.Nil}

	folders := seedFolderTree(ctx, tb, pool, p.FolderFanout, p.FolderDepth)
	if len(folders) == 0 {
		tb.Fatal("profile produced no folders")
	}
	w.MidFolder = folders[len(folders)/2]
	deepFolder := folders[len(folders)-1]

	users := make([]uuid.UUID, 0, p.Users)
	for i := 0; i < p.Users; i++ {
		users = append(users, insertUser(ctx, tb, pool, fmt.Sprintf("u%d@bench.test", i)))
	}
	if len(users) == 0 {
		tb.Fatal("profile produced no users")
	}
	w.DeepSubject = users[0]

	var deepRole uuid.UUID
	for _, f := range folders {
		for r := 0; r < p.RolesPerFolder; r++ {
			role := insertRole(ctx, tb, pool, fmt.Sprintf("role-%s-%d", short(f), r), f)
			seedRoleCaps(ctx, tb, pool, role, p.CapsPerRole)
			if f == deepFolder && r == 0 {
				deepRole = role
			}
		}
	}
	if deepRole == uuid.Nil {
		tb.Fatal("no role homed in the deep folder (RolesPerFolder must be >= 1)")
	}
	w.RequestRole = deepRole

	w.LeafAsset = insertSSHAsset(ctx, tb, pool, deepFolder, "leaf")
	w.LeafLogins = []string{"deploy"}
	seedSSHLogin(ctx, tb, pool, w.LeafAsset, "deploy")
	w.RequestAsset = w.LeafAsset

	insertUserBinding(ctx, tb, pool, deepRole, deepFolder, w.DeepSubject)

	// Opt-in data-plane inheritance self-edge: role_grants(deepRole, deepRole,
	// 'parent') lets the held closure descend a deepRole binding held on
	// deepFolder onto that folder's child assets (the leaf). Without it a
	// folder-scoped binding never reaches a contained asset, so DeepSubject
	// could not ssh:connect to LeafAsset.
	insertRoleGrant(ctx, tb, pool, deepRole, deepRole, "parent")

	// Group-nesting chain: DeepSubject ∈ g0 ∈ g1 ∈ … ∈ g[depth]; bind the top group
	// to deepRole on deepFolder so the held closure traverses the chain.
	if p.GroupChainDepth > 0 {
		chain := make([]uuid.UUID, p.GroupChainDepth)
		for i := range chain {
			chain[i] = insertGroup(ctx, tb, pool, fmt.Sprintf("g%d-%s", i, short(deepFolder)), deepFolder)
		}
		addUserToGroup(ctx, tb, pool, chain[0], w.DeepSubject)
		for i := 0; i+1 < len(chain); i++ {
			addGroupToGroup(ctx, tb, pool, chain[i+1], chain[i]) // chain[i] is a member of chain[i+1]
		}
		insertGroupBinding(ctx, tb, pool, deepRole, deepFolder, chain[len(chain)-1])
	}

	// Role-rewrite cascade: a chain of source roles feeding deepRole, so holding the
	// tail role confers deepRole through RoleGrantDepth rewrite edges.
	prev := deepRole
	for i := 0; i < p.RoleGrantDepth; i++ {
		src := insertRole(ctx, tb, pool, fmt.Sprintf("src-%d-%s", i, short(deepFolder)), deepFolder)
		seedRoleCaps(ctx, tb, pool, src, p.CapsPerRole)
		insertRoleGrant(ctx, tb, pool, prev, src, viaFor(p.RoleGrantVia, i)) // holding src ⇒ prev
		prev = src
	}

	// Request policy on the leaf asset with an approver subject and a requester group.
	policy := insertRequestPolicy(ctx, tb, pool, deepRole, w.LeafAsset)
	w.Approver = insertUser(ctx, tb, pool, "approver@bench.test")
	insertApproverSubject(ctx, tb, pool, policy, w.Approver)

	// Requester eligibility: a group that is a `requester` subject on the policy. Its
	// members may RequestAccess deepRole on the leaf asset — they hold no role, so they
	// are eligible AND not already-active. The write benches add members per iteration.
	w.RequesterGroup = insertGroup(ctx, tb, pool, fmt.Sprintf("req-grp-%s", short(deepFolder)), deepFolder)
	insertRequesterSubject(ctx, tb, pool, policy, w.RequesterGroup)

	// Seed PendingRequests distinct pending requests, each from a distinct eligible
	// requester user (satisfying uq_pending_request(requester,role,asset)). This feeds
	// the ListPendingApprovals N+1 sentinel: the approver can approve all of them, so a
	// per-request approver resolution shows up as queries/op climbing with the count.
	for i := 0; i < p.PendingRequests; i++ {
		ru := insertUser(ctx, tb, pool, fmt.Sprintf("pending-req-%d@bench.test", i))
		addUserToGroup(ctx, tb, pool, w.RequesterGroup, ru)
		w.PendingReqs = append(w.PendingReqs, insertOpenRequest(ctx, tb, pool, ru, deepRole, w.LeafAsset))
	}
	if len(w.PendingReqs) > 0 {
		w.PendingReq = w.PendingReqs[0]
	}

	// Live sessions: LiveSessions rows for DeepSubject on LeafAsset, spread over a
	// small worker set, all recorded present in worker_presence. The revocation
	// benches re-evaluate these.
	if p.LiveSessions > 0 {
		w.Workers = []string{"worker-a", "worker-b"}
		for _, wk := range w.Workers {
			upsertWorkerPresence(ctx, tb, pool, wk)
		}
		for i := 0; i < p.LiveSessions; i++ {
			wk := w.Workers[i%len(w.Workers)]
			insertLiveSession(ctx, tb, pool, w.DeepSubject, w.LeafAsset, wk)
			w.LivePairs = append(w.LivePairs, UserAsset{User: w.DeepSubject, Asset: w.LeafAsset})
		}
	}

	return w
}

func short(id uuid.UUID) string { return id.String()[:8] }

func seedFolderTree(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, fanout, depth int) []uuid.UUID {
	tb.Helper()
	var all []uuid.UUID
	var grow func(parent *uuid.UUID, level int)
	grow = func(parent *uuid.UUID, level int) {
		if level > depth {
			return
		}
		for i := 0; i < fanout; i++ {
			id := insertFolder(ctx, tb, pool, fmt.Sprintf("n-d%d-f%d-%d", level, i, len(all)), parent)
			all = append(all, id)
			grow(&id, level+1)
		}
	}
	grow(nil, 0)
	return all
}

func insertFolder(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, name string, parent *uuid.UUID) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	var err error
	if parent == nil {
		err = pool.QueryRow(ctx, `INSERT INTO folders(name) VALUES($1) RETURNING id`, name).Scan(&id)
	} else {
		err = pool.QueryRow(ctx, `INSERT INTO folders(name, parent_id) VALUES($1,$2) RETURNING id`, name, *parent).Scan(&id)
	}
	if err != nil {
		tb.Fatalf("insert folder: %v", err)
	}
	return id
}

func insertUser(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, email string) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO users(email, display_name) VALUES($1,$1) RETURNING id`, email).Scan(&id); err != nil {
		tb.Fatalf("insert user: %v", err)
	}
	return id
}

func insertRole(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, name string, folder uuid.UUID) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO roles(name, folder_id) VALUES($1,$2) RETURNING id`, name, folder).Scan(&id); err != nil {
		tb.Fatalf("insert role: %v", err)
	}
	return id
}

// seedRoleCaps inserts n capabilities into the role_capabilities TABLE; the first
// two are always ssh:connect and ssh:login:deploy so the role confers real connect
// access on ssh assets. qualifier is NOT NULL, so "no qualifier" is the empty string.
func seedRoleCaps(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, role uuid.UUID, n int) {
	tb.Helper()
	caps := [][3]string{{"ssh", "connect", ""}, {"ssh", "login", "deploy"}}
	for i := len(caps); i < n; i++ {
		caps = append(caps, [3]string{"ssh", "read", fmt.Sprintf("x%d", i)})
	}
	for _, c := range caps {
		if _, err := pool.Exec(ctx,
			`INSERT INTO role_capabilities(role_id, scope, action, qualifier) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			role, c[0], c[1], c[2]); err != nil {
			tb.Fatalf("insert cap: %v", err)
		}
	}
}

func insertSSHAsset(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, folder uuid.UUID, name string) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO assets(folder_id, name, labels, kind) VALUES($1,$2,'{}','ssh') RETURNING id`,
		folder, name).Scan(&id); err != nil {
		tb.Fatalf("insert asset: %v", err)
	}
	return id
}

// seedSSHLogin inserts an ssh_asset_login row (kind 'ca', no secret) so session
// admission finds a login on the asset.
func seedSSHLogin(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, asset uuid.UUID, login string) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO ssh_asset_login(asset_id, login, kind) VALUES($1,$2,'ca')`,
		asset, login); err != nil {
		tb.Fatalf("insert ssh login: %v", err)
	}
}

// insertUserBinding creates a role binding of role on folder for user. Bindings
// are standing-only in the current schema (migration 0007 dropped the kind
// column), so there is no kind to set.
func insertUserBinding(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, role, folder, user uuid.UUID) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_bindings(role_id, scope_folder_id, subject_user_id) VALUES($1,$2,$3)`,
		role, folder, user); err != nil {
		tb.Fatalf("insert binding: %v", err)
	}
}

func insertGroup(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, name string, folder uuid.UUID) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO groups(name, folder_id) VALUES($1,$2) RETURNING id`, name, folder).Scan(&id); err != nil {
		tb.Fatalf("insert group: %v", err)
	}
	return id
}

func addUserToGroup(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, group, user uuid.UUID) {
	tb.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO group_memberships(group_id, member_user_id) VALUES($1,$2)`, group, user); err != nil {
		tb.Fatalf("add user to group: %v", err)
	}
}

func addGroupToGroup(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, group, member uuid.UUID) {
	tb.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO group_memberships(group_id, member_group_id) VALUES($1,$2)`, group, member); err != nil {
		tb.Fatalf("add group to group: %v", err)
	}
}

// insertGroupBinding creates a STANDING role binding (role_bindings is standing-only,
// no kind column) of role on folder for a group subject.
func insertGroupBinding(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, role, folder, group uuid.UUID) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_bindings(role_id, scope_folder_id, subject_group_id) VALUES($1,$2,$3)`,
		role, folder, group); err != nil {
		tb.Fatalf("insert group binding: %v", err)
	}
}

// viaFor alternates edge kinds for the "mixed" setting; otherwise returns the
// configured via verbatim ("parent" or "same_object").
func viaFor(mode string, i int) string {
	if mode != "mixed" {
		return mode
	}
	if i%2 == 0 {
		return "parent"
	}
	return "same_object"
}

func insertRoleGrant(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, role, source uuid.UUID, via string) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_grants(role_id, source_role_id, via) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
		role, source, via); err != nil {
		tb.Fatalf("insert role grant: %v", err)
	}
}

// insertRequestPolicy makes `role` requestable on `asset` (scope_asset_id set,
// required_approvals defaults to 1). name must match ^[a-z0-9_-]+$.
func insertRequestPolicy(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, role, asset uuid.UUID) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO request_policies(role_id, scope_asset_id, name) VALUES($1,$2,$3) RETURNING id`,
		role, asset, "bench-policy-"+short(asset)).Scan(&id); err != nil {
		tb.Fatalf("insert request policy: %v", err)
	}
	return id
}

func insertApproverSubject(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, policy, user uuid.UUID) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO request_policy_subjects(policy_id, kind, subject_user_id) VALUES($1,'approver',$2)`,
		policy, user); err != nil {
		tb.Fatalf("insert approver subject: %v", err)
	}
}

// insertRequesterSubject adds a group as a `requester` subject on the policy, making
// its members eligible to RequestAccess the policy's role.
func insertRequesterSubject(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, policy, group uuid.UUID) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO request_policy_subjects(policy_id, kind, subject_group_id) VALUES($1,'requester',$2)`,
		policy, group); err != nil {
		tb.Fatalf("insert requester subject: %v", err)
	}
}

// insertLiveSession writes an active live_sessions row (unique id per row; id is the
// token jti / replay guard). protocol/principals/client_key_fp are NOT NULL.
func insertLiveSession(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, user, asset uuid.UUID, worker string) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO live_sessions(id, user_id, asset_id, worker_id, protocol, principals, client_key_fp)
		 VALUES(gen_random_uuid(), $1, $2, $3, 'ssh', ARRAY['deploy'], 'SHA256:benchfp')`,
		user, asset, worker); err != nil {
		tb.Fatalf("insert live session: %v", err)
	}
}

// upsertWorkerPresence records a worker as present now (presence column is last_seen_at).
func upsertWorkerPresence(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, worker string) {
	tb.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO worker_presence(worker_id) VALUES($1)
		 ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now()`,
		worker); err != nil {
		tb.Fatalf("upsert worker presence: %v", err)
	}
}

// insertOpenRequest inserts a pending access_request. requested_duration,
// granted_duration (interval) and required_approvals (int) are all NOT NULL.
func insertOpenRequest(ctx context.Context, tb testing.TB, pool *pgxpool.Pool, requester, role, asset uuid.UUID) uuid.UUID {
	tb.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO access_requests(requester_user_id, role_id, asset_id, requested_duration, required_approvals, granted_duration, status)
		 VALUES($1,$2,$3, interval '1 hour', 1, interval '1 hour', 'pending') RETURNING id`,
		requester, role, asset).Scan(&id); err != nil {
		tb.Fatalf("insert open request: %v", err)
	}
	return id
}
