//go:build bench

package bench

import "github.com/google/uuid"

// Profile tunes the nesting/inheritance dimensions plus flat entity counts. Every
// knob is independent so a benchmark can isolate a single axis.
type Profile struct {
	Name string

	// Dimension 1 — folder tree shape.
	FolderFanout int
	FolderDepth  int

	// Dimension 2 — group-in-group nesting.
	GroupChainDepth int
	GroupsPerFolder int
	UsersPerLeafGrp int

	// Dimension 3 — role rewrite cascade.
	RolesPerFolder int
	RoleGrantDepth int
	RoleGrantVia   string // "parent" | "same_object" | "mixed"

	// Dimension 4 — binding + policy fan-out.
	BindingsPerFolder int
	PoliciesPerFolder int

	// Session-runtime fixtures.
	LiveSessions int

	// Flat counts.
	Users       int
	CapsPerRole int
}

// World holds the reference handles a benchmark exercises, populated by Generate.
// The "deep" subject sits at the tail of the group+role cascade so held-closure
// re-evaluation is maximally expensive (the worst case the profiles target).
type World struct {
	DeepSubject uuid.UUID // user holding a role that grants ssh caps on LeafAsset
	LeafAsset   uuid.UUID // deepest asset the deep subject can reach
	LeafLogins  []string  // allowed ssh logins configured on LeafAsset
	MidFolder   uuid.UUID // a folder mid-tree (browse anchor)
	RootParent  uuid.UUID // uuid.Nil — the tree root, for root-level browse

	// Requestability / approvals fixtures.
	RequestRole  uuid.UUID // a role the deep subject may request on RequestAsset
	RequestAsset uuid.UUID
	Approver     uuid.UUID // a user who is an approver for (RequestRole, RequestAsset)
	PendingReq   uuid.UUID // an open access request (for Approve/ListPendingApprovals)

	// Revocation fixtures: live (user,asset) pairs whose workers are "connected".
	LivePairs []UserAsset
	Workers   []string
}

// UserAsset is a live-session (user,asset) pair for the revocation benches.
type UserAsset struct {
	User  uuid.UUID
	Asset uuid.UUID
}

// Profiles is the named profile set, all under the ~10k medium ceiling.
var Profiles = []Profile{
	{
		Name: "wide", FolderFanout: 20, FolderDepth: 2,
		GroupChainDepth: 2, GroupsPerFolder: 2, UsersPerLeafGrp: 3,
		RolesPerFolder: 2, RoleGrantDepth: 2, RoleGrantVia: "parent",
		BindingsPerFolder: 3, PoliciesPerFolder: 2, LiveSessions: 50,
		Users: 200, CapsPerRole: 3,
	},
	{
		Name: "deep", FolderFanout: 2, FolderDepth: 8,
		GroupChainDepth: 6, GroupsPerFolder: 1, UsersPerLeafGrp: 2,
		RolesPerFolder: 1, RoleGrantDepth: 6, RoleGrantVia: "mixed",
		BindingsPerFolder: 1, PoliciesPerFolder: 1, LiveSessions: 50,
		Users: 200, CapsPerRole: 3,
	},
	{
		Name: "dense-inheritance", FolderFanout: 4, FolderDepth: 4,
		GroupChainDepth: 4, GroupsPerFolder: 3, UsersPerLeafGrp: 3,
		RolesPerFolder: 3, RoleGrantDepth: 4, RoleGrantVia: "mixed",
		BindingsPerFolder: 3, PoliciesPerFolder: 3, LiveSessions: 100,
		Users: 300, CapsPerRole: 4,
	},
	{
		Name: "balanced", FolderFanout: 4, FolderDepth: 3,
		GroupChainDepth: 3, GroupsPerFolder: 2, UsersPerLeafGrp: 2,
		RolesPerFolder: 2, RoleGrantDepth: 3, RoleGrantVia: "parent",
		BindingsPerFolder: 2, PoliciesPerFolder: 2, LiveSessions: 50,
		Users: 200, CapsPerRole: 3,
	},
}

// benchProfiles returns the profiles to run, honoring BENCH_PROFILE=<name> to
// restrict to one.
func benchProfiles() []Profile {
	want := profileFilter()
	if want == "" {
		return Profiles
	}
	for _, p := range Profiles {
		if p.Name == want {
			return []Profile{p}
		}
	}
	return nil
}
