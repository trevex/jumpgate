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
// It uses ConnectCapabilities, so the same scope cascade as management applies —
// an ssh:login:<login> binding held globally, on any ancestor folder, or on the
// asset itself all confer connect — with the sole carve-out that the literal `**`
// super-capability does NOT grant proxy access on its own.
func EntitledLogins(ctx context.Context, a scopeCapabilitiesReader, userID, assetID uuid.UUID, allowedLogins []string) ([]string, error) {
	return EntitledLoginsFor(ctx, a, userID, assetID, SSHLoginPrefix, allowedLogins)
}

// EntitledLoginsFor resolves the caller's connect capabilities on the asset and
// returns the subset of allowedLogins entitled under the given prefix
// (SSHLoginPrefix / DBLoginPrefix). Order-preserving; returns nil when empty.
func EntitledLoginsFor(ctx context.Context, a scopeCapabilitiesReader, userID, assetID uuid.UUID, prefix string, allowedLogins []string) ([]string, error) {
	caps, err := ConnectCapabilities(ctx, a, userID, assetID)
	if err != nil {
		return nil, err
	}
	return caps.EntitledLoginsFor(prefix, allowedLogins), nil
}
