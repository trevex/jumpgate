package rpc_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

func authClient(t *testing.T, url, email, pw string) string {
	t.Helper()
	c := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	resp, err := c.Login(context.Background(), connect.NewRequest(&authv1.LoginRequest{Email: email, Password: pw}))
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return resp.Msg.Token
}

func TestGroupsAndMemberships(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	g1, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "sre"}), tok))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	g2, err := c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "platform"}), tok))
	if err != nil {
		t.Fatalf("create group2: %v", err)
	}
	u, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "carol@x", DisplayName: "Carol", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := c.AddUserToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: g1.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("add user to group: %v", err)
	}
	if _, err := c.AddGroupToGroup(ctx, withToken(connect.NewRequest(&identityv1.AddGroupToGroupRequest{
		GroupId: g2.Msg.Group.Id, MemberGroupId: g1.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("add group to group: %v", err)
	}

	// non-admin is rejected
	seedUser(t, pool, "user@x", "password123", false)
	uc := authClient(t, url, "user@x", "password123")
	_, err = c.CreateGroup(ctx, withToken(connect.NewRequest(&identityv1.CreateGroupRequest{Name: "nope"}), uc))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin create group code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	groups, err := c.ListGroups(ctx, withToken(connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups.Msg.Groups) < 2 {
		t.Fatalf("want >=2 groups, got %d", len(groups.Msg.Groups))
	}
}
