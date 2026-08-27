package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
)

// Authorizer resolves access over the control-plane Postgres. The shared
// authorization closures live in the DB as recursive SQL functions (authz_held /
// authz_global_held / …), reached through the static sqlc queries on q.
type Authorizer struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New returns an Authorizer backed by Postgres.
func New(pool *pgxpool.Pool) *Authorizer {
	return &Authorizer{pool: pool, q: sqlc.New(pool)}
}

// queries returns the sqlc query set, lazily initialising q for authorizers built
// as a bare struct literal (internal tests) rather than via New.
func (s *Authorizer) queries() *sqlc.Queries {
	if s.q == nil {
		s.q = sqlc.New(s.pool)
	}
	return s.q
}

// uuidArg wraps a uuid.UUID as a non-null pgtype.UUID for sqlc params typed
// pgtype.UUID (the authz functions never require NULL ids).
func uuidArg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// textArg wraps a string as a non-null pgtype.Text for sqlc params typed pgtype.Text.
func textArg(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

// nullableUUIDArg maps the browse "parent" convention (uuid.Nil == root/NULL) to a
// pgtype.UUID: uuid.Nil becomes SQL NULL, any other id a non-null value.
func nullableUUIDArg(id uuid.UUID) pgtype.UUID {
	if id == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}

// The forward "held" closure — (role, object) pairs a user holds via standing
// bindings, active JIT access_grants, and the role_grants rewrite graph — is the
// dual of RoleResolver.HoldsRole. It is group-aware and cycle-safe, lives in the
// DB as the authz_held function, and is the single source Check and the
// Requestable tier draw from, so they cannot diverge.

// VisibleAssets returns every asset the user can see — those on which the user
// holds ≥1 Active (standing) role OR has ≥1 Requestable role (an effective
// request_policy for which the user is an eligible requester). Assets with neither
// are omitted entirely (existence-hiding: they must not be disclosed).
func (s *Authorizer) VisibleAssets(ctx context.Context, userID uuid.UUID) ([]AssetVisibility, error) {
	type acc struct {
		active bool
		seen   map[uuid.UUID]struct{}
		roles  []uuid.UUID
	}
	byAsset := map[uuid.UUID]*acc{}
	var order []uuid.UUID
	get := func(assetID uuid.UUID) *acc {
		a := byAsset[assetID]
		if a == nil {
			a = &acc{seen: map[uuid.UUID]struct{}{}}
			byAsset[assetID] = a
			order = append(order, assetID)
		}
		return a
	}
	addRole := func(a *acc, roleID uuid.UUID) {
		if _, ok := a.seen[roleID]; !ok {
			a.seen[roleID] = struct{}{}
			a.roles = append(a.roles, roleID)
		}
	}

	// Active tier: assets held via the explicit role-rewrite graph (standing).
	heldAssets, err := s.queries().HeldAssets(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("visible assets (active): %w", err)
	}
	for _, row := range heldAssets {
		a := get(uuid.UUID(row.ObjectID.Bytes))
		a.active = true
		addRole(a, uuid.UUID(row.RoleID.Bytes))
	}

	// Requestable tier: assets with ≥1 role requestable-but-not-active under the
	// request_policy eligibility model.
	req, err := s.visibleRequestable(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("visible assets (requestable): %w", err)
	}
	for _, ra := range req {
		addRole(get(ra.AssetID), ra.RoleID)
	}

	out := make([]AssetVisibility, 0, len(order))
	for _, id := range order {
		a := byAsset[id]
		out = append(out, AssetVisibility{AssetID: id, Active: a.active, RoleIDs: a.roles})
	}
	return out, nil
}

// RolesOnAsset returns the user's active and requestable roles on one asset.
func (s *Authorizer) RolesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (AssetRoles, error) {
	var r AssetRoles

	// Active: roles held on the asset via the explicit role-rewrite graph.
	activeRoleIDs, err := s.queries().HeldRolesOnAsset(ctx, sqlc.HeldRolesOnAssetParams{User: uuidArg(userID), AssetID: uuidArg(assetID)})
	if err != nil {
		return AssetRoles{}, fmt.Errorf("roles on asset (active): %w", err)
	}
	activeSeen := map[uuid.UUID]struct{}{}
	for _, rid := range activeRoleIDs {
		roleID := uuid.UUID(rid.Bytes)
		if _, ok := activeSeen[roleID]; !ok {
			activeSeen[roleID] = struct{}{}
			r.Active = append(r.Active, roleID)
		}
	}

	// Requestable: roles requestable-but-not-active under the request_policy
	// eligibility model (active-exclusion is already applied inside the query).
	req, err := s.requestableRoles(ctx, userID, assetID)
	if err != nil {
		return AssetRoles{}, fmt.Errorf("roles on asset (requestable): %w", err)
	}
	r.Requestable = append(r.Requestable, req...)
	return r, nil
}

// CapabilitiesOnAsset returns every capability pattern the user holds on the asset
// via the held (standing) closure. It runs the closure ONCE and flattens all
// patterns, so callers testing several capabilities pay a single query. Glob
// matching happens in Go (CapMatch), keeping '*'/'**' semantics in one function.
func (s *Authorizer) CapabilitiesOnAsset(ctx context.Context, userID, assetID uuid.UUID) (Capabilities, error) {
	return s.CapabilitiesOnObject(ctx, userID, assetID, "asset")
}

// CapabilitiesOnObject returns every capability pattern the user holds on the
// object (kind "asset" or "folder") via the held closure — the object-dimension
// generalization of CapabilitiesOnAsset (glob matching stays in Go via CapMatch).
func (s *Authorizer) CapabilitiesOnObject(ctx context.Context, userID, objectID uuid.UUID, kind string) (Capabilities, error) {
	rows, err := s.queries().HeldCapabilitiesOnObject(ctx, sqlc.HeldCapabilitiesOnObjectParams{
		User:       uuidArg(userID),
		ObjectKind: textArg(kind),
		ObjectID:   uuidArg(objectID),
	})
	if err != nil {
		return nil, fmt.Errorf("capabilities on object: %w", err)
	}
	var caps Capabilities
	for _, r := range rows {
		caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
	}
	return caps, nil
}

// Check reports whether the user holds a role on the asset whose capability set
// grants the concrete `capability`. Single-query EXISTS over the same asset-object
// held closure CapabilitiesOnAsset uses, with the glob semantics ('*'/'**') pushed
// into the three-column predicate proven ≡ Go CapMatch by TestSQLCapMatchMatchesGo.
//
// It deliberately does NOT fold in the folder-management cascade or global
// scopeless bindings — that is CapabilitiesOnScope's job (the management plane);
// Check is the data-plane grant decision, keyed strictly to the asset object. A
// nonexistent asset matches no row, so EXISTS is false with no error. `capability`
// is internal (from workers), assumed concrete, not proto-validated.
func (s *Authorizer) Check(ctx context.Context, userID, assetID uuid.UUID, capability string) (bool, error) {
	reqScope, reqAction, reqQual := NormalizeCap(capability)
	ok, err := s.queries().HeldCheckAssetCapability(ctx, sqlc.HeldCheckAssetCapabilityParams{
		User:      uuidArg(userID),
		AssetID:   uuidArg(assetID),
		CapScope:  textArg(reqScope),
		CapAction: textArg(reqAction),
		CapQual:   textArg(reqQual),
	})
	if err != nil {
		return false, fmt.Errorf("check: %w", err)
	}
	return ok, nil
}

// CapabilitiesOnScope returns the capability patterns the user holds at a
// management scope. Global caps (scopeless standing bindings) ALWAYS apply. For a
// folder/asset scope, management authority CASCADES STRUCTURALLY down the folder
// tree — a cap held on folder F applies to F, its sub-folders, and every asset
// beneath — with NO per-role parent self-grant (unlike data-plane authz_held
// inheritance). One set-based query over authz_global_held ∪ authz_held on the
// in-scope objects (ltree @> for the down-tree cascade) replaces a 3–5 round-trip
// fan-out.
//
// Global caps come from authz_global_held, NOT authz_held rows with NULL object: a
// scopeless binding's `parent` rewrite arm cannot fire on a NULL object, whereas
// authz_global_held collapses both rewrite arms to plain edges — only it is the
// faithful global source. Existence-hiding: a nonexistent asset yields exactly the
// global caps with no error.
func (s *Authorizer) CapabilitiesOnScope(ctx context.Context, userID uuid.UUID, scope Scope) (Capabilities, error) {
	switch scope.Kind {
	case ScopeGlobal:
		// Global-only: no object dimension, so authz_global_held alone suffices.
		return s.globalHeldCapabilities(ctx, userID)
	case ScopeFolder:
		// authz_global_held ∪ authz_held on folders in the scope subtree (ltree @>).
		rows, err := s.queries().ScopeCapabilitiesFolder(ctx, sqlc.ScopeCapabilitiesFolderParams{User: userID, ScopeID: scope.ID})
		if err != nil {
			return nil, fmt.Errorf("capabilities on scope: %w", err)
		}
		var caps Capabilities
		for _, r := range rows {
			caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
		}
		return caps, nil
	case ScopeAsset:
		// authz_global_held ∪ authz_held on the asset or its ancestor-or-self folders.
		rows, err := s.queries().ScopeCapabilitiesAsset(ctx, sqlc.ScopeCapabilitiesAssetParams{User: uuidArg(userID), ScopeID: uuidArg(scope.ID)})
		if err != nil {
			return nil, fmt.Errorf("capabilities on scope: %w", err)
		}
		var caps Capabilities
		for _, r := range rows {
			caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
		}
		return caps, nil
	default:
		return nil, fmt.Errorf("unknown scope kind %d", scope.Kind)
	}
}
