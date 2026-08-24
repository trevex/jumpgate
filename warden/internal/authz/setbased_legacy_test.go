package authz

// Frozen legacy references for the "authz set-based query rework" (slices B/C).
//
// Each slice rewrites one production method into a single set-based query, gated
// by a differential test asserting the new implementation returns the SAME result
// as the pre-rewrite reference across the seeded probe matrix (setbased_diff_test.go).
// To keep that reference stable AFTER the production method is rewritten, this
// file freezes a VERBATIM copy of the pre-rewrite body under a `*Legacy` name that
// keeps calling the still-in-production helpers (globalHeldCapabilities,
// folderAncestorsAndSelf, capsOnFolders, CapabilitiesOnObject, assetFolderID).
//
// legacyMethods wires these frozen references into the same authzMethods struct
// the harness walks, overriding ONLY the fields a slice has rewritten so far; the
// rest stay bound to the exported (already-verified or not-yet-rewritten) methods.
// Later slices override more fields here.

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// capabilitiesOnScopeLegacy is the VERBATIM pre-B2 CapabilitiesOnScope body: the
// 3–5-round-trip fan-out over globalHeldCapabilities + folderAncestorsAndSelf +
// capsOnFolders (+ CapabilitiesOnObject + assetFolderID for assets). It is the
// differential oracle for the set-based rewrite in sql_authorizer.go — the two
// must produce identical Capabilities for every probe.
func (s *sqlAuthorizer) capabilitiesOnScopeLegacy(ctx context.Context, userID uuid.UUID, scope Scope) (Capabilities, error) {
	global, err := s.globalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, err
	}
	switch scope.Kind {
	case ScopeGlobal:
		return global, nil
	case ScopeFolder:
		ancestors, err := s.folderAncestorsAndSelf(ctx, scope.ID)
		if err != nil {
			return nil, fmt.Errorf("folder ancestors: %w", err)
		}
		fcaps, err := s.capsOnFolders(ctx, userID, ancestors)
		if err != nil {
			return nil, err
		}
		return append(global, fcaps...), nil
	case ScopeAsset:
		obj, err := s.CapabilitiesOnObject(ctx, userID, scope.ID, "asset")
		if err != nil {
			return nil, err
		}
		out := append(global, obj...)
		folderID, err := s.assetFolderID(ctx, scope.ID)
		if err != nil {
			// A nonexistent asset resolves to no folder caps (existence-hiding:
			// the handler performs the NotFound check after the cap gate, and
			// CapabilitiesOnObject above already returns empty for it). Any other
			// error is a real failure.
			if errors.Is(err, pgx.ErrNoRows) {
				return out, nil
			}
			return nil, fmt.Errorf("get asset: %w", err)
		}
		ancestors, err := s.folderAncestorsAndSelf(ctx, folderID)
		if err != nil {
			return nil, fmt.Errorf("folder ancestors: %w", err)
		}
		fcaps, err := s.capsOnFolders(ctx, userID, ancestors)
		if err != nil {
			return nil, err
		}
		return append(out, fcaps...), nil
	default:
		return nil, fmt.Errorf("unknown scope kind %d", scope.Kind)
	}
}

// legacyMethods binds the frozen `*Legacy` references into an authzMethods struct.
// It starts from newMethods (the exported, set-based-target methods) and OVERRIDES
// only the fields rewritten so far — B2 overrides capsOnScope. captureAuthzMatrix
// over legacyMethods therefore differs from captureAuthzMatrix over newMethods in
// exactly the rewritten method(s), focusing the differential diff on the rewrite.
func legacyMethods(s *sqlAuthorizer) authzMethods {
	m := newMethods(s)
	m.capsOnScope = s.capabilitiesOnScopeLegacy // B2
	return m
}
