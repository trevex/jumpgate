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
func EntitledLogins(ctx context.Context, a Authorizer, userID, assetID uuid.UUID, allowedLogins []string) ([]string, error) {
	var out []string
	for _, login := range allowedLogins {
		ok, err := a.Check(ctx, userID, assetID, "ssh:login:"+login)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, login)
		}
	}
	return out, nil
}
