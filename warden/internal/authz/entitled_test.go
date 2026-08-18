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
func (stubAuthorizer) VisibleAssets(context.Context, uuid.UUID) ([]authz.AssetVisibility, error) {
	return nil, nil
}
func (stubAuthorizer) RolesOnAsset(context.Context, uuid.UUID, uuid.UUID) (authz.AssetRoles, error) {
	return authz.AssetRoles{}, nil
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
