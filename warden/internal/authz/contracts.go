package authz

import "github.com/google/uuid"

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

// VisibleFolder is one visible folder plus whether the caller governs it (holds a
// management cap at/under it) vs sees it only as a breadcrumb on the path to an anchor.
type VisibleFolder struct {
	ID       uuid.UUID
	Governed bool
}
