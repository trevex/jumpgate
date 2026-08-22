package authz

import (
	"context"

	"github.com/google/uuid"
)

// ConnectCapabilities returns the caller's data-plane (proxy) capabilities on an
// asset. Unlike CapabilitiesOnAsset (asset-scoped only) it uses the full scope
// cascade — global + ancestor folders + the asset (CapabilitiesOnScope) — so a
// folder-scoped binding or an explicit global data-plane grant confers connect. The
// one carve-out: the literal `**` super-capability is dropped, because holding
// "manage everything" must not by itself grant proxy/SSH access to every target.
//
// Only the literal `**` string is stripped; scoped double-stars (ssh:**),
// single-stars (ssh:login:*), and concrete logins (ssh:login:deploy) all survive
// and continue to confer connect exactly as before.
func ConnectCapabilities(ctx context.Context, a Authorizer, userID, assetID uuid.UUID) (Capabilities, error) {
	caps, err := a.CapabilitiesOnScope(ctx, userID, AssetScope(assetID))
	if err != nil {
		return nil, err
	}
	out := make(Capabilities, 0, len(caps))
	for _, p := range caps {
		if p == "**" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
