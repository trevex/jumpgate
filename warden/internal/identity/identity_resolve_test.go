package identity_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

// TestResolveUserAndGroup pins direct email/name → id resolution (admin only, NotFound on miss).
func TestResolveUserAndGroup(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	seedUser(t, pool, "user@x", "password123", false)
	utok := authClient(t, url, "user@x", "password123")
	id := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// ResolveUser: existing seeded user resolves; admins only; miss → NotFound.
	ru, err := id.ResolveUser(ctx, withToken(connect.NewRequest(&identityv1.ResolveUserRequest{Email: "user@x"}), tok))
	if err != nil || ru.Msg.GetUserId() == "" {
		t.Fatalf("resolve user: %v / %q", err, ru.Msg.GetUserId())
	}
	if _, err := id.ResolveUser(ctx, withToken(connect.NewRequest(&identityv1.ResolveUserRequest{Email: "nobody@x"}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("resolve missing user = %v, want NotFound", connect.CodeOf(err))
	}
	if _, err := id.ResolveUser(ctx, withToken(connect.NewRequest(&identityv1.ResolveUserRequest{Email: "user@x"}), utok)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin resolve user = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// ResolveGroup: create a group, resolve by name; miss → NotFound; a non-admin
	// without the folder-scoped read cap → NotFound (existence-hidden, not
	// PermissionDenied — a delegated caller must not learn a group exists outside
	// their read scope).
	gr, err := id.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	rg, err := id.ResolveGroup(ctx, withToken(connect.NewRequest(&identityv1.ResolveGroupRequest{Name: "sre"}), tok))
	if err != nil || rg.Msg.GetGroupId() != gr.Msg.GetGroup().GetId() {
		t.Fatalf("resolve group: %v / %q vs %q", err, rg.Msg.GetGroupId(), gr.Msg.GetGroup().GetId())
	}
	if _, err := id.ResolveGroup(ctx, withToken(connect.NewRequest(&identityv1.ResolveGroupRequest{Name: "nope"}), tok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("resolve missing group = %v, want NotFound", connect.CodeOf(err))
	}
	if _, err := id.ResolveGroup(ctx, withToken(connect.NewRequest(&identityv1.ResolveGroupRequest{Name: "sre"}), utok)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("non-admin resolve group = %v, want NotFound", connect.CodeOf(err))
	}
}
