package identity_test

import (
	"context"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
)

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

	// ListGroupMembers reflects the added user + nested group.
	members, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: g1.Msg.Group.Id}), tok))
	if err != nil {
		t.Fatalf("list members g1: %v", err)
	}
	if len(members.Msg.Users) != 1 || members.Msg.Users[0].Id != u.Msg.User.Id {
		t.Fatalf("g1 users = %+v, want [carol]", members.Msg.Users)
	}
	membersG2, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: g2.Msg.Group.Id}), tok))
	if err != nil {
		t.Fatalf("list members g2: %v", err)
	}
	if len(membersG2.Msg.Groups) != 1 || membersG2.Msg.Groups[0].Id != g1.Msg.Group.Id {
		t.Fatalf("g2 groups = %+v, want [g1]", membersG2.Msg.Groups)
	}

	// RemoveUserFromGroup drops the user membership.
	if _, err := c.RemoveUserFromGroup(ctx, withToken(connect.NewRequest(&identityv1.RemoveUserFromGroupRequest{
		GroupId: g1.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), tok)); err != nil {
		t.Fatalf("remove user from group: %v", err)
	}
	after, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: g1.Msg.Group.Id}), tok))
	if err != nil {
		t.Fatalf("list members after remove: %v", err)
	}
	if len(after.Msg.Users) != 0 {
		t.Fatalf("g1 users after remove = %+v, want []", after.Msg.Users)
	}

	// RemoveGroupFromGroup drops the nested-group membership.
	if _, err := c.RemoveGroupFromGroup(ctx, withToken(connect.NewRequest(&identityv1.RemoveGroupFromGroupRequest{
		GroupId: g2.Msg.Group.Id, MemberGroupId: g1.Msg.Group.Id,
	}), tok)); err != nil {
		t.Fatalf("remove group from group: %v", err)
	}
	afterG2, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: g2.Msg.Group.Id}), tok))
	if err != nil {
		t.Fatalf("list members g2 after remove: %v", err)
	}
	if len(afterG2.Msg.Groups) != 0 {
		t.Fatalf("g2 groups after remove = %+v, want []", afterG2.Msg.Groups)
	}

	// Non-admin is rejected on the lifecycle admin RPCs.
	if _, err := c.RemoveUserFromGroup(ctx, withToken(connect.NewRequest(&identityv1.RemoveUserFromGroupRequest{
		GroupId: g1.Msg.Group.Id, UserId: u.Msg.User.Id,
	}), uc)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin RemoveUserFromGroup = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := c.ListGroupMembers(ctx, withToken(connect.NewRequest(&identityv1.ListGroupMembersRequest{GroupId: g1.Msg.Group.Id}), uc)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin ListGroupMembers = %v, want PermissionDenied", connect.CodeOf(err))
	}
}
