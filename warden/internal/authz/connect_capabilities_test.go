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

// TestBareStarStarConfersNoConnect is the behavioral guard for the central
// connect-vs-management invariant: a user holding ONLY the bare `**`
// super-capability (and no explicit ssh:login grant) must be denied connect at
// EVERY connect-decision entrypoint that routes through ConnectCapabilities.
//
// This test goes RED if someone changes ConnectCapabilities to stop stripping the
// literal `**`, or wires a connect entrypoint to the un-stripped CapabilitiesOnScope
// set — silently granting a bare-`**` admin proxy access into every asset. The
// invariant is documented at the top of connect_capabilities.go; this pins it.
func TestBareStarStarConfersNoConnect(t *testing.T) {
	ctx := context.Background()
	// The user holds ONLY the bare ** (as CapabilitiesOnScope would return it).
	a := scopeStub{scoped: authz.Capabilities{"**"}}
	userID, assetID := uuid.New(), uuid.New()

	// Entrypoint 1: EntitledLogins (credential mint / SetupSession re-auth predicate)
	// must yield an EMPTY login set against an asset that offers ssh logins.
	logins, err := authz.EntitledLogins(ctx, a, userID, assetID, []string{"deploy", "root"})
	if err != nil {
		t.Fatal(err)
	}
	if len(logins) != 0 {
		t.Fatalf("bare ** must confer no login entitlement; got %v", logins)
	}

	// Entrypoint 2: ConnectCapabilities (the set GetAssetAccess.capabilities and the
	// SetupSession re-auth adjudicate against) must not allow ANY ssh:login.
	caps, err := authz.ConnectCapabilities(ctx, a, userID, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 0 {
		t.Fatalf("bare ** must strip to an empty connect set; got %v", caps)
	}
	if caps.Allows("ssh:login:deploy") {
		t.Fatal("bare ** must NOT allow ssh:login:deploy (connect must strip **)")
	}
	if caps.Allows("ssh:login:root") {
		t.Fatal("bare ** must NOT allow ssh:login:root (connect must strip **)")
	}
	if caps.EntitledLogins([]string{"deploy", "root"}) != nil {
		t.Fatal("bare ** connect set must entitle no login")
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
