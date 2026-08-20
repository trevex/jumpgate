package authz

import (
	"context"

	"github.com/google/uuid"
)

// EntitledLogins returns the subset of allowedLogins for which userID holds the
// "ssh:login:<login>" capability on assetID via the held closure. This is the
// data-plane connect predicate (a non-empty result means "may open an SSH
// session") and the exact set the CredentialBroker certifies as cert principals.
// Order-preserving; returns nil (not empty slice) when the intersection is empty.
//
// It fetches the held capability set ONCE (one closure query) and intersects in
// Go, rather than a Check per login — the result is identical (each Check ran the
// same closure + CapMatch("ssh:login:<login>")).
func EntitledLogins(ctx context.Context, a Authorizer, userID, assetID uuid.UUID, allowedLogins []string) ([]string, error) {
	caps, err := a.CapabilitiesOnAsset(ctx, userID, assetID)
	if err != nil {
		return nil, err
	}
	return caps.EntitledLogins(allowedLogins), nil
}
