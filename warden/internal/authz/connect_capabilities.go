package authz

import (
	"context"

	"github.com/google/uuid"
)

// scopeCapabilitiesReader is the narrow seam ConnectCapabilities and EntitledLogins
// consume: the scope-cascade capability lookup. *Authorizer satisfies it; tests
// supply a stub.
type scopeCapabilitiesReader interface {
	CapabilitiesOnScope(ctx context.Context, userID uuid.UUID, scope Scope) (Capabilities, error)
}

// ConnectCapabilities returns the caller's data-plane (proxy) capabilities on an
// asset, using the full scope cascade (global + ancestor folders + asset), so a
// folder-scoped binding or a global data-plane grant confers connect. Carve-out:
// only the literal `**` super-capability is dropped — holding "manage everything"
// must not by itself grant proxy/SSH access. Scoped double-stars (ssh:**),
// single-stars (ssh:login:*), and concrete logins all survive.
func ConnectCapabilities(ctx context.Context, a scopeCapabilitiesReader, userID, assetID uuid.UUID) (Capabilities, error) {
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
