package authz

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// globalHeldCapabilities returns the capability patterns the user holds GLOBALLY
// via scopeless standing bindings (scope_folder_id IS NULL AND scope_asset_id IS
// NULL) closed over the role_grants rewrite graph. The closure itself lives in the
// database as the authz_global_held SQL function (the scopeless analogue of
// authz_held); this method reaches it through the static GlobalHeldCapabilities
// query. A deactivated user holds nothing (enforced inside the function).
func (s *sqlAuthorizer) globalHeldCapabilities(ctx context.Context, userID uuid.UUID) (Capabilities, error) {
	rows, err := s.queries().GlobalHeldCapabilities(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("global held: %w", err)
	}
	var caps Capabilities
	for _, r := range rows {
		caps = append(caps, ReconstructCap(r.Scope, r.Action, r.Qualifier))
	}
	return caps, nil
}
