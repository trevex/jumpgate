// Package authz defines the authorization seam and its implementations.
//
// The Authorizer interface is the single boundary all callers use to ask access
// questions. The M2a implementation resolves everything with recursive SQL over
// Postgres (sqlAuthorizer). An OpenFGA-backed implementation can be added later
// behind this same interface without touching callers.
package authz

import (
	"context"

	"github.com/google/uuid"
)

// AssetVisibility describes a user's relationship to one asset.
type AssetVisibility struct {
	AssetID uuid.UUID
	// Active is true when the user holds at least one Active (standing) role on the
	// asset (directly or via the role_grants rewrite graph / group nesting). If
	// false but the asset appears in VisibleAssets, the user is Requestable-only.
	Active bool
	// RoleIDs are the roles granting the user access to this asset (active and/or
	// requestable), deduplicated.
	RoleIDs []uuid.UUID
}

// AssetRoles splits the roles a user holds on an asset into active vs requestable.
type AssetRoles struct {
	Active      []uuid.UUID
	Requestable []uuid.UUID
}

// Authorizer answers relationship-based access questions for a user.
type Authorizer interface {
	// Check reports whether the user has the given capability on the asset via any
	// active (standing) role. Requestable eligibility does NOT grant capabilities.
	Check(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error)

	// CapabilitiesOnAsset returns the capability patterns the user holds on the asset
	// via the held (standing) closure — one query, for callers that test several
	// capabilities (e.g. per-login entitlement + record-exempt) without re-running
	// the closure per capability.
	CapabilitiesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (Capabilities, error)

	// CapabilitiesOnScope returns caps the user holds at a management scope:
	// globally-held always, plus (folder/asset scope) caps held on that object.
	CapabilitiesOnScope(ctx context.Context, userID uuid.UUID, scope Scope) (Capabilities, error)

	// VisibleAssets returns every asset the user can see — those on which the user
	// holds at least one Active (standing) role OR has at least one Requestable role
	// (an effective request_policy for which the user is an eligible requester).
	// Assets with neither are omitted entirely (they must not be disclosed).
	VisibleAssets(ctx context.Context, userID uuid.UUID) ([]AssetVisibility, error)

	// RolesOnAsset returns the user's active and requestable roles on one asset.
	RolesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (AssetRoles, error)

	// VisibleFoldersUnder returns the ids of the folders directly under `parent`
	// (parent == uuid.Nil is the tree root: folders with parent_id IS NULL) that
	// the user may SEE, unioning the management axis with the access axis. A folder
	// is visible when the user holds "catalog:folder:read" on it (management) OR its
	// subtree contains an asset the user can access (VisibleAssets). With cascade,
	// the whole subtree under `parent` is considered as candidate folders, not just
	// the immediate children.
	VisibleFoldersUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)

	// VisibleAssetsUnder returns the ids of the assets under `parent` (a folder;
	// uuid.Nil is the root) the user may SEE, unioning management with access. An
	// asset is visible when the user holds "catalog:asset:read" on its folder
	// (management) OR the asset is in VisibleAssets (active or requestable). Without
	// cascade only assets in the immediate child folders of `parent` are considered;
	// with cascade the whole subtree is. Because assets always live in a folder,
	// parent == uuid.Nil without cascade yields no assets (the root holds none).
	VisibleAssetsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)

	// VisibleRolesUnder returns the ids of the roles homed under `parent` (a folder;
	// uuid.Nil is the tree root: roles with folder_id IS NULL) the user may SEE,
	// unioning the management axis with the access axis. A role is visible when the
	// user holds "access:role:read" on its home-folder scope (management) OR the user
	// holds the role (via the standing/grant closure) OR the role is requestable to
	// the user. A folder-less (global) role has no folder scope, so it is manageable
	// ONLY via a globally-held capability. Without cascade only roles homed directly
	// in `parent` (or, for uuid.Nil, the folder-less roles) are considered; with
	// cascade the whole subtree under `parent` (or every role, for uuid.Nil) is.
	VisibleRolesUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)

	// VisibleGroupsUnder returns the ids of the groups homed under `parent` (a folder;
	// uuid.Nil is the tree root: groups with folder_id IS NULL) the user may SEE,
	// unioning the management axis with the access axis. A group is visible when the
	// user holds "identity:group:read" on its home-folder scope (management) OR the
	// user is a (transitive) member of the group. A folder-less (global) group has no
	// folder scope, so it is manageable ONLY via a globally-held capability. Without
	// cascade only groups homed directly in `parent` (or, for uuid.Nil, the
	// folder-less groups) are considered; with cascade the whole subtree under
	// `parent` (or every group, for uuid.Nil) is.
	VisibleGroupsUnder(ctx context.Context, userID, parent uuid.UUID, cascade bool) ([]uuid.UUID, error)

	// IsMember reports whether userID is a (transitive) member of groupID.
	// Returns false for deactivated users. Used by GetGroupAccess to distinguish
	// a member with no management caps (success) from a total stranger (NotFound).
	IsMember(ctx context.Context, userID, groupID uuid.UUID) (bool, error)
}
