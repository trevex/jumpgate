package authz_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

type stubAuthorizer struct{ allow map[string]bool }

func (s stubAuthorizer) Check(_ context.Context, _, _ uuid.UUID, capability string) (bool, error) {
	return s.allow[capability], nil
}

// CapabilitiesOnAsset returns exactly the capabilities the stub was seeded to
// allow, so Capabilities.Allows reproduces Check's answers (the seeded caps are
// concrete, so CapMatch reduces to equality).
func (s stubAuthorizer) CapabilitiesOnAsset(_ context.Context, _, _ uuid.UUID) (authz.Capabilities, error) {
	return s.seededCaps(), nil
}

// CapabilitiesOnScope returns the same seeded caps for any scope, so Allows
// reproduces Check globally and on every object.
func (s stubAuthorizer) CapabilitiesOnScope(_ context.Context, _ uuid.UUID, _ authz.Scope) (authz.Capabilities, error) {
	return s.seededCaps(), nil
}

func (s stubAuthorizer) seededCaps() authz.Capabilities {
	var caps authz.Capabilities
	for c, ok := range s.allow {
		if ok {
			caps = append(caps, c)
		}
	}
	return caps
}
func (stubAuthorizer) VisibleAssets(context.Context, uuid.UUID) ([]authz.AssetVisibility, error) {
	return nil, nil
}
func (stubAuthorizer) RolesOnAsset(context.Context, uuid.UUID, uuid.UUID) (authz.AssetRoles, error) {
	return authz.AssetRoles{}, nil
}
func (stubAuthorizer) VisibleFoldersUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (stubAuthorizer) VisibleAssetsUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (stubAuthorizer) VisibleRolesUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (stubAuthorizer) VisibleGroupsUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (stubAuthorizer) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return false, nil
}

func TestEntitledLoginsIntersects(t *testing.T) {
	a := stubAuthorizer{allow: map[string]bool{"ssh:login:root": false, "ssh:login:deploy": true}}
	got, err := authz.EntitledLogins(context.Background(), a, uuid.New(), uuid.New(), []string{"root", "deploy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "deploy" {
		t.Fatalf("got %v, want [deploy]", got)
	}
}

func TestEntitledLoginsEmpty(t *testing.T) {
	a := stubAuthorizer{allow: map[string]bool{}}
	got, err := authz.EntitledLogins(context.Background(), a, uuid.New(), uuid.New(), []string{"root"})
	if err != nil || got != nil {
		t.Fatalf("want (nil,nil), got (%v,%v)", got, err)
	}
}
