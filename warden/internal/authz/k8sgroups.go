package authz

import (
	"context"

	"github.com/google/uuid"
)

// EntitledK8sGroups returns the concrete k8s group names the user holds on the
// asset (materialized from held k8s:group:* capabilities). Unlike login
// entitlement, groups are an enumerated attribute (see ConcreteQualifiers), so
// wildcard grants yield nothing. Empty result = no k8s access (connect gate).
func EntitledK8sGroups(ctx context.Context, a scopeCapabilitiesReader, userID, assetID uuid.UUID) ([]string, error) {
	caps, err := ConnectCapabilities(ctx, a, userID, assetID)
	if err != nil {
		return nil, err
	}
	return caps.ConcreteQualifiers(K8sGroupPrefix), nil
}
