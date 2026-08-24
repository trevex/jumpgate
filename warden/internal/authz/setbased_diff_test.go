package authz

// Differential-test harness #2 for the "authz set-based query rework" (slices
// B/C). Slices B/C re-express the six per-scope visibility/capability methods —
// CapabilitiesOnScope, Check, VisibleFoldersUnder, VisibleAssetsUnder,
// VisibleRolesUnder, VisibleGroupsUnder (plus FolderPathVisible) — as single
// set-based SQL queries. Each rewrite is gated by asserting the new
// implementation returns the SAME result as the frozen `*Legacy` reference
// across a seeded user matrix, mirroring how ltree_test.go keeps the recursive
// walks as references.
//
// This file (B1) delivers the harness itself:
//
//   - seedMatrix: a representative folder tree + a matrix of probe users that
//     exercises every visibility/capability path (see matrixSeed doc).
//   - authzMethods / newMethods: a struct of method values so the same matrix
//     walk can target either the current methods or the future `*Legacy` ones.
//   - captureAuthzMatrix: walks (user × scope/asset/parent/cap × cascade) and
//     records a canonical, order-independent result string per probe.
//   - requireMatrixEqual: key-by-key diff of two captured matrices.
//   - TestSetbasedMatrixHarness: proves the harness is (a) deterministic and
//     (b) discriminating (hand-computed expectations).
//
// B2/B3/C reuse seedMatrix, authzMethods, newMethods, captureAuthzMatrix and
// requireMatrixEqual verbatim — the differential body of each of those slices is
// just: `want := captureAuthzMatrix(ctx, t, legacyMethods(s), s, probes)` vs
// `got := captureAuthzMatrix(ctx, t, newMethods(s), s, probes)`; the legacy method
// values wire into the SAME authzMethods struct. Keep these signatures stable.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// ── Seed ────────────────────────────────────────────────────────────────────

// matrixSeed carries every id a differential probe needs. Each probe user is
// bound on a DIFFERENT folder/asset so its scope is distinguishable in the
// captured matrix. The tree (all roots are top-level unless nested):
//
//	assetTeam ⊃ assetChild ⊃ (asset assetX)      — assetAdmin: catalog:asset:read @ assetTeam
//	roleTeam                  homes role roleHomed — roleAdmin:  access:role:read  @ roleTeam
//	groupTeam                 homes group groupHomed — groupAdmin: identity:group:read @ groupTeam
//	connTeam  ⊃ (asset connAsset + ssh_asset_login 'deploy') — connector: ssh:login:* @ connTeam
//	reqTeam   ⊃ (asset reqAsset)                  — requester: standing requesterRole + policy(targetRole requestable)
//
// Users:
//   - admin:       global (scopeless) `**` binding — sees/governs everything.
//   - assetAdmin:  catalog:asset:read @ assetTeam — manage-sees assets in that subtree only.
//   - roleAdmin:   access:role:read   @ roleTeam  — manage-sees roleHomed.
//   - groupAdmin:  identity:group:read @ groupTeam — manage-sees groupHomed.
//   - connector:   ssh:login:*        @ connTeam  — connect-visible on connAsset, NOT manage.
//   - requester:   standing requesterRole @ reqAsset + policy — reqAsset Requestable (Active=false).
//   - deactivated: a global `**` binding BUT deactivated_at set — must see NOTHING.
//   - stranger:    no bindings at all — sees nothing.
//
// Also seeded: a global (folder_id NULL) role and group, so the folder-less arm
// of VisibleRolesUnder / VisibleGroupsUnder is exercised.
type matrixSeed struct {
	// Probe users, keyed by a stable label used in the captured matrix keys.
	users map[string]uuid.UUID

	// Folders spanning the tree.
	assetTeam, assetChild uuid.UUID
	roleTeam              uuid.UUID
	groupTeam             uuid.UUID
	connTeam              uuid.UUID
	reqTeam               uuid.UUID

	// Assets.
	assetX    uuid.UUID // under assetChild (assetAdmin subtree)
	connAsset uuid.UUID // under connTeam, has an ssh_asset_login row
	reqAsset  uuid.UUID // under reqTeam, made requestable to requester

	// Folder-homed nodes + globals.
	roleHomed   uuid.UUID // role homed in roleTeam
	groupHomed  uuid.UUID // group homed in groupTeam
	globalRole  uuid.UUID // folder_id NULL
	globalGroup uuid.UUID // folder_id NULL

	// Access-model roles used by the requester arm.
	requesterRole uuid.UUID // held standing by requester on reqAsset
	targetRole    uuid.UUID // requestable to requester on reqAsset via policy

	// allFolders / allAssets are the full sets, for building probe targets and
	// hand-computed "admin sees all" expectations.
	allFolders []uuid.UUID
	allAssets  []uuid.UUID
	allRoles   []uuid.UUID
	allGroups  []uuid.UUID
}

// userLabels is the deterministic order the matrix walk iterates probe users.
var userLabels = []string{
	"admin", "assetAdmin", "roleAdmin", "groupAdmin",
	"connector", "requester", "deactivated", "stranger",
}

// seedMatrix builds the representative tree + probe-user matrix described on
// matrixSeed and returns every id a differential probe needs. It creates all
// rows via the generated query layer (gen.New) plus one direct ssh_asset_login
// insert, matching the seed() pattern in sql_authorizer_test.go.
func seedMatrix(t *testing.T, pool *pgxpool.Pool) matrixSeed {
	t.Helper()
	ctx := context.Background()
	q := gen.New(pool)

	mkUser := func(email string) uuid.UUID { return mustCreateUser(t, q, email) }
	mkFolderQ := func(name string, parent pgtype.UUID) uuid.UUID {
		f, err := q.CreateFolder(ctx, gen.CreateFolderParams{Name: name, ParentID: parent})
		if err != nil {
			t.Fatalf("seedMatrix: folder %q: %v", name, err)
		}
		return f.ID
	}
	mkAsset := func(folder uuid.UUID, name string) uuid.UUID {
		a, err := q.CreateAsset(ctx, gen.CreateAssetParams{FolderID: folder, Name: name, Labels: []byte("{}"), Kind: "ssh"})
		if err != nil {
			t.Fatalf("seedMatrix: asset %q: %v", name, err)
		}
		return a.ID
	}
	// bindFolder attaches a standing role (with the given caps) to a user on a
	// folder scope.
	bindFolder := func(user, folder uuid.UUID, roleName string, capsBytes []byte) uuid.UUID {
		r := createRoleWithCaps(t, ctx, q, roleName, pgtype.UUID{}, capsBytes)
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID: r.ID, ScopeFolderID: pgUUID(folder), SubjectUserID: pgUUID(user),
		}); err != nil {
			t.Fatalf("seedMatrix: bind %q @ folder: %v", roleName, err)
		}
		return r.ID
	}
	// bindGlobal attaches a scopeless (global) standing role to a user.
	bindGlobal := func(user uuid.UUID, roleName string, capsBytes []byte) uuid.UUID {
		r := createRoleWithCaps(t, ctx, q, roleName, pgtype.UUID{}, capsBytes)
		if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
			RoleID: r.ID, SubjectUserID: pgUUID(user),
		}); err != nil {
			t.Fatalf("seedMatrix: bind global %q: %v", roleName, err)
		}
		return r.ID
	}

	s := matrixSeed{users: map[string]uuid.UUID{}}

	// ── Tree ──────────────────────────────────────────────────────────────
	s.assetTeam = mkFolderQ("asset-team", pgtype.UUID{})
	s.assetChild = mkFolderQ("asset-child", pgUUID(s.assetTeam))
	s.roleTeam = mkFolderQ("role-team", pgtype.UUID{})
	s.groupTeam = mkFolderQ("group-team", pgtype.UUID{})
	s.connTeam = mkFolderQ("conn-team", pgtype.UUID{})
	s.reqTeam = mkFolderQ("req-team", pgtype.UUID{})

	s.assetX = mkAsset(s.assetChild, "asset-x")
	s.connAsset = mkAsset(s.connTeam, "conn-asset")
	s.reqAsset = mkAsset(s.reqTeam, "req-asset")

	// ssh_asset_login on connAsset so the connect-visibility arm has a login to
	// entitle. kind='ca' needs no secret_id (see 0017_ssh_per_login schema).
	if _, err := q.UpsertSSHAssetLogin(ctx, gen.UpsertSSHAssetLoginParams{
		AssetID: s.connAsset, Login: "deploy", Kind: "ca",
	}); err != nil {
		t.Fatalf("seedMatrix: ssh_asset_login: %v", err)
	}

	// ── Folder-homed nodes + globals ──────────────────────────────────────
	roleHomed := createRoleWithCaps(t, ctx, q, "role-homed", pgUUID(s.roleTeam), caps("db:read"))
	s.roleHomed = roleHomed.ID
	globalRole := createRoleWithCaps(t, ctx, q, "global-role", pgtype.UUID{}, caps("db:read"))
	s.globalRole = globalRole.ID

	groupHomed, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "group-homed", FolderID: pgUUID(s.groupTeam)})
	if err != nil {
		t.Fatalf("seedMatrix: group-homed: %v", err)
	}
	s.groupHomed = groupHomed.ID
	globalGroup, err := q.CreateGroup(ctx, gen.CreateGroupParams{Name: "global-group"})
	if err != nil {
		t.Fatalf("seedMatrix: global-group: %v", err)
	}
	s.globalGroup = globalGroup.ID

	// ── Probe users + bindings ────────────────────────────────────────────
	admin := mkUser("m-admin@x")
	bindGlobal(admin, "m-admin-role", caps("**"))
	s.users["admin"] = admin

	assetAdmin := mkUser("m-asset-admin@x")
	bindFolder(assetAdmin, s.assetTeam, "m-asset-admin-role", caps("catalog:asset:read"))
	s.users["assetAdmin"] = assetAdmin

	roleAdmin := mkUser("m-role-admin@x")
	bindFolder(roleAdmin, s.roleTeam, "m-role-admin-role", caps("access:role:read"))
	s.users["roleAdmin"] = roleAdmin

	groupAdmin := mkUser("m-group-admin@x")
	bindFolder(groupAdmin, s.groupTeam, "m-group-admin-role", caps("identity:group:read"))
	s.users["groupAdmin"] = groupAdmin

	// connector: folder-scoped ssh:login:* (connect-only) on connTeam. Bound as a
	// standing role on the folder; the connect arm folds the folder ancestor chain
	// into CapabilitiesOnScope(AssetScope(connAsset)).
	connector := mkUser("m-connector@x")
	bindFolder(connector, s.connTeam, "m-connector-role", caps("ssh:login:*"))
	s.users["connector"] = connector

	// requester: holds requesterRole STANDING on reqAsset; a request_policy makes
	// targetRole requestable there with requester_role=requesterRole. So reqAsset
	// is Requestable-visible (Active=true for requesterRole; targetRole requestable).
	requester := mkUser("m-requester@x")
	requesterRole := createRoleWithCaps(t, ctx, q, "m-requester-role", pgtype.UUID{}, caps("db:read"))
	targetRole := createRoleWithCaps(t, ctx, q, "m-target-role", pgtype.UUID{}, caps("db:admin"))
	s.requesterRole = requesterRole.ID
	s.targetRole = targetRole.ID
	if _, err := q.CreateRoleBinding(ctx, gen.CreateRoleBindingParams{
		RoleID: requesterRole.ID, ScopeAssetID: pgUUID(s.reqAsset), SubjectUserID: pgUUID(requester),
	}); err != nil {
		t.Fatalf("seedMatrix: bind requesterRole: %v", err)
	}
	if _, err := q.CreateRequestPolicy(ctx, gen.CreateRequestPolicyParams{
		RoleID: targetRole.ID, ScopeAssetID: pgUUID(s.reqAsset), RequiredApprovals: 1, RequesterRoleID: pgUUID(requesterRole.ID),
	}); err != nil {
		t.Fatalf("seedMatrix: request_policy: %v", err)
	}
	s.users["requester"] = requester

	// deactivated: bound with a global `**` (would otherwise see everything) but
	// deactivated — must see NOTHING everywhere.
	deactivated := mkUser("m-deactivated@x")
	bindGlobal(deactivated, "m-deactivated-role", caps("**"))
	if err := q.DeactivateUser(ctx, deactivated); err != nil {
		t.Fatalf("seedMatrix: deactivate: %v", err)
	}
	s.users["deactivated"] = deactivated

	// stranger: no bindings at all.
	s.users["stranger"] = mkUser("m-stranger@x")

	// ── Full sets (for probe targets + admin "sees all" expectations) ─────
	s.allFolders = mustAllIDs(t, pool, "SELECT id FROM folders")
	s.allAssets = mustAllIDs(t, pool, "SELECT id FROM assets")
	s.allRoles = mustAllIDs(t, pool, "SELECT id FROM roles")
	s.allGroups = mustAllIDs(t, pool, "SELECT id FROM groups")
	return s
}

// mustAllIDs runs a single-uuid-column query and returns all ids.
func mustAllIDs(t *testing.T, pool *pgxpool.Pool, query string) []uuid.UUID {
	t.Helper()
	rows, err := pool.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("mustAllIDs(%q): %v", query, err)
	}
	defer rows.Close()
	out, err := scanUUIDs(rows)
	if err != nil {
		t.Fatalf("mustAllIDs(%q) scan: %v", query, err)
	}
	return out
}

// ── Capture harness ───────────────────────────────────────────────────────

// authzMethods is a struct of the seven method values the differential matrix
// probes. newMethods wires it to the current sqlAuthorizer methods; B2/B3/C wire
// the SAME struct to the frozen `*Legacy` methods and diff the two captures. Do
// not change these signatures — the B2/B3/C differential tests depend on them.
type authzMethods struct {
	capsOnScope       func(ctx context.Context, user uuid.UUID, scope Scope) (Capabilities, error)
	check             func(ctx context.Context, user, asset uuid.UUID, capability string) (bool, error)
	visFolders        func(ctx context.Context, user, parent uuid.UUID, cascade bool) ([]VisibleFolder, error)
	visAssets         func(ctx context.Context, user, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)
	visRoles          func(ctx context.Context, user, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)
	visGroups         func(ctx context.Context, user, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)
	folderPathVisible func(ctx context.Context, user, folderID uuid.UUID) (bool, error)
}

// newMethods binds the CURRENT (set-based-target) sqlAuthorizer methods into an
// authzMethods struct. B2/B3/C provide a parallel constructor over the `*Legacy`
// methods and feed both into captureAuthzMatrix.
func newMethods(s *sqlAuthorizer) authzMethods {
	return authzMethods{
		capsOnScope:       s.CapabilitiesOnScope,
		check:             s.Check,
		visFolders:        s.VisibleFoldersUnder,
		visAssets:         s.VisibleAssetsUnder,
		visRoles:          s.VisibleRolesUnder,
		visGroups:         s.VisibleGroupsUnder,
		folderPathVisible: s.FolderPathVisible,
	}
}

// matrixProbes is the fixed set of probe targets the matrix walk sweeps for
// EVERY user. Deterministic and derived from the seed so the capture is stable.
type matrixProbes struct {
	scopes  []labeledScope // for capsOnScope
	assets  []labeledID    // for check (asset dimension)
	caps    []string       // for check (capability dimension)
	parents []labeledID    // for visFolders/visAssets/visRoles/visGroups
	folders []labeledID    // for folderPathVisible
}

type labeledScope struct {
	label string
	scope Scope
}
type labeledID struct {
	label string
	id    uuid.UUID
}

// defaultProbes builds a fixed, seed-derived probe set touching every scope
// kind, several folders/assets across the tree, a spread of capabilities and a
// definitely-absent one, and uuid.Nil + several folders as browse parents. Both
// cascade=true and cascade=false are swept by captureAuthzMatrix.
func defaultProbes(s matrixSeed) matrixProbes {
	scopes := []labeledScope{
		{"global", GlobalScope()},
		{"f:assetTeam", FolderScope(s.assetTeam)},
		{"f:assetChild", FolderScope(s.assetChild)},
		{"f:roleTeam", FolderScope(s.roleTeam)},
		{"f:groupTeam", FolderScope(s.groupTeam)},
		{"f:connTeam", FolderScope(s.connTeam)},
		{"f:reqTeam", FolderScope(s.reqTeam)},
		{"a:assetX", AssetScope(s.assetX)},
		{"a:connAsset", AssetScope(s.connAsset)},
		{"a:reqAsset", AssetScope(s.reqAsset)},
	}
	assets := []labeledID{
		{"assetX", s.assetX},
		{"connAsset", s.connAsset},
		{"reqAsset", s.reqAsset},
	}
	capsList := []string{
		"catalog:asset:read",
		"catalog:folder:read",
		"access:role:read",
		"identity:group:read",
		"db:read",
		"db:admin",
		"ssh:login:deploy",
		"nonexistent:cap:here", // definitely absent for everyone but a ** admin
	}
	parents := []labeledID{
		{"root", uuid.Nil},
		{"assetTeam", s.assetTeam},
		{"assetChild", s.assetChild},
		{"roleTeam", s.roleTeam},
		{"groupTeam", s.groupTeam},
		{"connTeam", s.connTeam},
		{"reqTeam", s.reqTeam},
	}
	folders := []labeledID{
		{"assetTeam", s.assetTeam},
		{"assetChild", s.assetChild},
		{"roleTeam", s.roleTeam},
		{"groupTeam", s.groupTeam},
		{"connTeam", s.connTeam},
		{"reqTeam", s.reqTeam},
	}
	return matrixProbes{scopes: scopes, assets: assets, caps: capsList, parents: parents, folders: folders}
}

// captureAuthzMatrix walks (probe user × probe target × cascade) for every
// method in m and records a canonical, order-independent result string per
// probe, keyed by (method, user-label, target, cascade). The canonicalization
// makes the map safe to compare via requireMatrixEqual across two captures:
//
//   - uuid slices are sorted;
//   - CapabilitiesOnScope patterns are reconstructed-then-sorted;
//   - VisibleFolder results include the Governed flag (sorted by id);
//   - Check / FolderPathVisible record the bool.
//
// Any method error is recorded as an "ERR:" value (so a divergence in error
// behaviour is also caught) rather than failing the walk.
func captureAuthzMatrix(ctx context.Context, t *testing.T, m authzMethods, s matrixSeed, p matrixProbes) map[string]string {
	t.Helper()
	out := map[string]string{}
	set := func(key, val string) {
		if _, dup := out[key]; dup {
			t.Fatalf("captureAuthzMatrix: duplicate key %q — probe labels must be unique", key)
		}
		out[key] = val
	}

	for _, label := range userLabels {
		user := s.users[label]

		// CapabilitiesOnScope over every probe scope.
		for _, ps := range p.scopes {
			caps, err := m.capsOnScope(ctx, user, ps.scope)
			set(k("capsOnScope", label, ps.label, false), capsResult(caps, err))
		}

		// Check over (asset × cap).
		for _, pa := range p.assets {
			for _, c := range p.caps {
				ok, err := m.check(ctx, user, pa.id, c)
				set(k("check", label, pa.label+"|"+c, false), boolResult(ok, err))
			}
		}

		// The four "under a parent" methods, both cascade modes.
		for _, cascade := range []bool{false, true} {
			for _, pp := range p.parents {
				vf, err := m.visFolders(ctx, user, pp.id, cascade)
				set(k("visFolders", label, pp.label, cascade), folderResult(vf, err))

				va, err := m.visAssets(ctx, user, pp.id, cascade)
				set(k("visAssets", label, pp.label, cascade), idResult(va, err))

				vr, err := m.visRoles(ctx, user, pp.id, cascade)
				set(k("visRoles", label, pp.label, cascade), idResult(vr, err))

				vg, err := m.visGroups(ctx, user, pp.id, cascade)
				set(k("visGroups", label, pp.label, cascade), idResult(vg, err))
			}
		}

		// FolderPathVisible over several folders (no cascade dimension).
		for _, pf := range p.folders {
			ok, err := m.folderPathVisible(ctx, user, pf.id)
			set(k("folderPathVisible", label, pf.label, false), boolResult(ok, err))
		}
	}
	return out
}

// k builds a canonical, collision-free matrix key from (method, user, target,
// cascade).
func k(method, user, target string, cascade bool) string {
	return fmt.Sprintf("%s|u=%s|t=%s|c=%t", method, user, target, cascade)
}

// idResult canonicalizes a uuid slice (sorted) or an error into a comparable
// string.
func idResult(ids []uuid.UUID, err error) string {
	if err != nil {
		return "ERR:" + err.Error()
	}
	ss := make([]string, len(ids))
	for i, id := range ids {
		ss[i] = id.String()
	}
	sort.Strings(ss)
	return "[" + strings.Join(ss, ",") + "]"
}

// folderResult canonicalizes a []VisibleFolder — each entry as "id:governed",
// sorted by id — or an error.
func folderResult(vf []VisibleFolder, err error) string {
	if err != nil {
		return "ERR:" + err.Error()
	}
	ss := make([]string, len(vf))
	for i, f := range vf {
		ss[i] = fmt.Sprintf("%s:%t", f.ID, f.Governed)
	}
	sort.Strings(ss)
	return "[" + strings.Join(ss, ",") + "]"
}

// capsResult canonicalizes a Capabilities set — or an error. Capabilities is
// already a []string of canonical patterns; sorting+deduping makes it
// order-independent (the closure emits DISTINCT rows in arbitrary order).
func capsResult(caps Capabilities, err error) string {
	if err != nil {
		return "ERR:" + err.Error()
	}
	seen := map[string]struct{}{}
	var ss []string
	for _, p := range caps {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		ss = append(ss, p)
	}
	sort.Strings(ss)
	return "{" + strings.Join(ss, ",") + "}"
}

// boolResult canonicalizes a bool or an error.
func boolResult(ok bool, err error) string {
	if err != nil {
		return "ERR:" + err.Error()
	}
	return fmt.Sprintf("%t", ok)
}

// requireMatrixEqual asserts two captured matrices are identical key-by-key,
// reporting every mismatch (and any missing keys) with a readable diff. `want`
// is the reference (e.g. the `*Legacy` capture); `got` is the candidate.
func requireMatrixEqual(t *testing.T, want, got map[string]string) {
	t.Helper()
	var diffs []string
	for key, wv := range want {
		gv, ok := got[key]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("  %s: missing in got (want %s)", key, wv))
			continue
		}
		if gv != wv {
			diffs = append(diffs, fmt.Sprintf("  %s:\n      want %s\n      got  %s", key, wv, gv))
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			diffs = append(diffs, fmt.Sprintf("  %s: extra in got (%s)", key, got[key]))
		}
	}
	if len(diffs) > 0 {
		sort.Strings(diffs)
		t.Fatalf("matrix mismatch (%d):\n%s", len(diffs), strings.Join(diffs, "\n"))
	}
}

// ── Self-test ───────────────────────────────────────────────────────────────

// TestSetbasedMatrixHarness proves the B1 harness is sound before any `*Legacy`
// method exists: (1) the capture is deterministic/order-independent (two runs
// over the same authorizer produce identical matrices), and (2) the matrix is
// discriminating — a set of hand-computed expectations shows it is meaningful,
// not vacuously all-empty.
func TestSetbasedMatrixHarness(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := seedMatrix(t, pool)
	a := &sqlAuthorizer{pool: pool}
	probes := defaultProbes(s)

	// (1) Determinism/repeatability: two captures over the same authorizer must be
	// identical. (Order-independence of each result is guaranteed structurally by
	// the sort in the *Result canonicalizers, not by this check.)
	m := newMethods(a)
	first := captureAuthzMatrix(ctx, t, m, s, probes)
	second := captureAuthzMatrix(ctx, t, m, s, probes)
	requireMatrixEqual(t, first, second)

	// (2) Discriminating hand-computed expectations. Robust to ordering — all use
	// the set helpers or read the canonical strings from the capture.

	// admin: global ** — sees & governs ALL folders, all assets/roles/groups.
	for _, cascade := range []bool{false, true} {
		af, err := a.VisibleFoldersUnder(ctx, s.users["admin"], uuid.Nil, cascade)
		mustNoErr(t, err)
		if cascade {
			requireSameSet(t, s.allFolders, FolderIDsOf(af), "admin visFolders(root,cascade)")
			for _, f := range af {
				if !f.Governed {
					t.Fatalf("admin: folder %s must be governed", f.ID)
				}
			}
		}
	}
	adminAssets, err := a.VisibleAssetsUnder(ctx, s.users["admin"], uuid.Nil, true)
	mustNoErr(t, err)
	requireSameSet(t, s.allAssets, adminAssets, "admin visAssets(root,cascade)")
	adminRoles, err := a.VisibleRolesUnder(ctx, s.users["admin"], uuid.Nil, true)
	mustNoErr(t, err)
	requireSameSet(t, s.allRoles, adminRoles, "admin visRoles(root,cascade)")
	adminGroups, err := a.VisibleGroupsUnder(ctx, s.users["admin"], uuid.Nil, true)
	mustNoErr(t, err)
	requireSameSet(t, s.allGroups, adminGroups, "admin visGroups(root,cascade)")
	// admin's ** is a global MANAGEMENT scope binding: CapabilitiesOnScope folds it
	// in at every scope (management authority is scopeless-global), so `**` allows
	// even an otherwise-absent capability. (Check, the data-plane connect path, is
	// a DIFFERENT closure — a scopeless binding confers no object-dimensioned held
	// role there — so admin's ** does NOT make Check(assetX) true; that is the
	// management-vs-connect boundary, pinned by the connector arm below.)
	adminScopeCaps, err := a.CapabilitiesOnScope(ctx, s.users["admin"], AssetScope(s.assetX))
	mustNoErr(t, err)
	if !adminScopeCaps.Allows("nonexistent:cap:here") {
		t.Fatalf("admin ** must allow any cap at any scope; caps=%v", adminScopeCaps)
	}

	// deactivated & stranger: NOTHING anywhere. Every capture value for these two
	// users must be an empty result (empty set / false), no ERR.
	for _, label := range []string{"deactivated", "stranger"} {
		for key, val := range first {
			if !strings.Contains(key, "|u="+label+"|") {
				continue
			}
			if !isEmptyResult(val) {
				t.Fatalf("%s must see nothing, but %s = %s", label, key, val)
			}
		}
	}

	// assetAdmin: manage-sees assets in its subtree (assetX under assetTeam), but a
	// Check for access:role:read is false, and it does NOT govern outside assetTeam.
	aaAssets, err := a.VisibleAssetsUnder(ctx, s.users["assetAdmin"], s.assetTeam, true)
	mustNoErr(t, err)
	requireContains(t, aaAssets, s.assetX)
	if ok, err := a.Check(ctx, s.users["assetAdmin"], s.assetX, "access:role:read"); err != nil || ok {
		t.Fatalf("assetAdmin Check(access:role:read, assetX) = %v,%v; want false", ok, err)
	}
	// assetAdmin must NOT manage-see the connector's asset (different subtree).
	aaConn, err := a.VisibleAssetsUnder(ctx, s.users["assetAdmin"], s.connTeam, true)
	mustNoErr(t, err)
	requireNotContains(t, aaConn, s.connAsset)

	// connector: connect-visible on connAsset (appears in visAssets for connTeam)
	// but does NOT manage-see it, and CapabilitiesOnScope(AssetScope(connAsset))
	// does NOT allow catalog:asset:read.
	connAssets, err := a.VisibleAssetsUnder(ctx, s.users["connector"], s.connTeam, false)
	mustNoErr(t, err)
	requireContains(t, connAssets, s.connAsset)
	connCaps, err := a.CapabilitiesOnScope(ctx, s.users["connector"], AssetScope(s.connAsset))
	mustNoErr(t, err)
	if connCaps.Allows("catalog:asset:read") {
		t.Fatalf("connector must NOT manage-see connAsset; caps=%v", connCaps)
	}
	if !connCaps.Allows("ssh:login:deploy") {
		t.Fatalf("connector must entitle ssh:login:deploy on connAsset; caps=%v", connCaps)
	}
	// A pure connector never manage-sees the asset's folder as governed. But it
	// DOES see the path (breadcrumb) — assert governed=false on connTeam.
	connFolders, err := a.VisibleFoldersUnder(ctx, s.users["connector"], uuid.Nil, false)
	mustNoErr(t, err)
	for _, f := range connFolders {
		if f.ID == s.connTeam && f.Governed {
			t.Fatalf("connector must NOT govern connTeam (connect-only)")
		}
	}

	// requester: sees reqAsset (Requestable). Active is true for the standing
	// requesterRole, and targetRole is Requestable — VisibleAssets includes it.
	reqAssets, err := a.VisibleAssetsUnder(ctx, s.users["requester"], s.reqTeam, false)
	mustNoErr(t, err)
	requireContains(t, reqAssets, s.reqAsset)
	roles, err := a.RolesOnAsset(ctx, s.users["requester"], s.reqAsset)
	mustNoErr(t, err)
	requireContains(t, roles.Active, s.requesterRole)
	requireContains(t, roles.Requestable, s.targetRole)
	// The requester does not manage the asset — no catalog:asset:read.
	if ok, err := a.Check(ctx, s.users["requester"], s.reqAsset, "catalog:asset:read"); err != nil || ok {
		t.Fatalf("requester Check(catalog:asset:read) = %v,%v; want false", ok, err)
	}

	// roleAdmin: manage-sees the folder-homed role, not the global role.
	raRoles, err := a.VisibleRolesUnder(ctx, s.users["roleAdmin"], s.roleTeam, true)
	mustNoErr(t, err)
	requireContains(t, raRoles, s.roleHomed)
	requireNotContains(t, raRoles, s.globalRole)

	// groupAdmin: manage-sees the folder-homed group, not the global group.
	gaGroups, err := a.VisibleGroupsUnder(ctx, s.users["groupAdmin"], s.groupTeam, true)
	mustNoErr(t, err)
	requireContains(t, gaGroups, s.groupHomed)
	requireNotContains(t, gaGroups, s.globalGroup)
}

// TestSetbasedCapabilitiesOnScopeDiff (B2) gates the set-based CapabilitiesOnScope
// rewrite: it captures the probe matrix twice over the SAME authorizer — once with
// legacyMethods (capsOnScope = the frozen 3–5-round-trip capabilitiesOnScopeLegacy)
// and once with newMethods (capsOnScope = the single set-based query) — and asserts
// they are identical. Because only capsOnScope differs between the two method sets,
// any divergence localizes to the rewrite. A mismatch means the SQL is wrong; fix
// the SQL, not the test.
func TestSetbasedCapabilitiesOnScopeDiff(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := seedMatrix(t, pool)
	a := &sqlAuthorizer{pool: pool}
	probes := defaultProbes(s)

	old := captureAuthzMatrix(ctx, t, legacyMethods(a), s, probes)
	got := captureAuthzMatrix(ctx, t, newMethods(a), s, probes)
	requireMatrixEqual(t, old, got)
}

// isEmptyResult reports whether a captured result string denotes "nothing"
// (empty id set / empty caps set / false), i.e. the value a user who sees
// nothing must produce for EVERY method. Never treats an ERR: value as empty.
func isEmptyResult(val string) bool {
	switch val {
	case "[]", "{}", "false":
		return true
	default:
		return false
	}
}
