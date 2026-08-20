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

	// VisibleAssets returns every asset the user can see — those on which the user
	// holds at least one Active (standing) role OR has at least one Requestable role
	// (an effective request_policy for which the user is an eligible requester).
	// Assets with neither are omitted entirely (they must not be disclosed).
	VisibleAssets(ctx context.Context, userID uuid.UUID) ([]AssetVisibility, error)

	// RolesOnAsset returns the user's active and requestable roles on one asset.
	RolesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (AssetRoles, error)
}
