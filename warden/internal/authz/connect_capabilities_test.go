package authz_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/trevex/jumpgate/warden/internal/authz"
)

// scopeStub returns a fixed capability set from CapabilitiesOnScope (the cascade
// seam ConnectCapabilities consumes) and nothing from CapabilitiesOnAsset, so a
// test that still reaches the asset-scoped path would visibly regress.
type scopeStub struct{ scoped authz.Capabilities }

func (scopeStub) Check(context.Context, uuid.UUID, uuid.UUID, string) (bool, error) {
	return false, nil
}
func (scopeStub) CapabilitiesOnAsset(context.Context, uuid.UUID, uuid.UUID) (authz.Capabilities, error) {
	return nil, nil
}
func (s scopeStub) CapabilitiesOnScope(context.Context, uuid.UUID, authz.Scope) (authz.Capabilities, error) {
	return s.scoped, nil
}
func (scopeStub) VisibleAssets(context.Context, uuid.UUID) ([]authz.AssetVisibility, error) {
	return nil, nil
}
func (scopeStub) RolesOnAsset(context.Context, uuid.UUID, uuid.UUID) (authz.AssetRoles, error) {
	return authz.AssetRoles{}, nil
}
func (scopeStub) VisibleFoldersUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (scopeStub) VisibleAssetsUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (scopeStub) VisibleRolesUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (scopeStub) VisibleGroupsUnder(context.Context, uuid.UUID, uuid.UUID, bool) ([]uuid.UUID, error) {
	return nil, nil
}
func (scopeStub) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return false, nil
}

func TestConnectCapabilitiesDropsDoubleStar(t *testing.T) {
	a := scopeStub{scoped: authz.Capabilities{"**", "ssh:login:deploy"}}
	got, err := authz.ConnectCapabilities(context.Background(), a, uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ssh:login:deploy" {
		t.Fatalf("got %v, want [ssh:login:deploy] (** dropped)", got)
	}
	if got.Allows("ssh:login:deploy") != true {
		t.Fatal("must still allow ssh:login:deploy")
	}
	// The stripped ** must not confer proxy access to some other login.
	if got.Allows("ssh:login:root") {
		t.Fatal("stripped ** must not grant ssh:login:root")
	}
}

func TestConnectCapabilitiesDoubleStarOnly(t *testing.T) {
	a := scopeStub{scoped: authz.Capabilities{"**"}}
	got, err := authz.ConnectCapabilities(context.Background(), a, uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty (only ** held)", got)
	}
	if got.EntitledLogins([]string{"deploy"}) != nil {
		t.Fatal("** alone must confer no login entitlement")
	}
}

// A scoped ** (ssh:**) is NOT the literal ** carve-out and must be kept.
func TestConnectCapabilitiesKeepsScopedDoubleStar(t *testing.T) {
	a := scopeStub{scoped: authz.Capabilities{"ssh:**"}}
	got, err := authz.ConnectCapabilities(context.Background(), a, uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ssh:**" {
		t.Fatalf("got %v, want [ssh:**] (scoped ** kept)", got)
	}
	if got.EntitledLogins([]string{"deploy"}) == nil {
		t.Fatal("ssh:** must confer login entitlement")
	}
}
