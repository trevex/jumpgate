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

func adminToken(t *testing.T, url string) string {
	t.Helper()
	c := authv1connect.NewAuthServiceClient(http.DefaultClient, url)
	resp, err := c.Login(context.Background(), connect.NewRequest(&authv1.LoginRequest{Email: "admin@x", Password: "supersecret"}))
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	return resp.Msg.Token
}

func withToken[T any](req *connect.Request[T], tok string) *connect.Request[T] {
	req.Header().Set("Authorization", "Bearer "+tok)
	return req
}

func TestUsersCRUDRequiresAdmin(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	ctx := context.Background()

	// No token → not allowed
	_, err := c.CreateUser(ctx, connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "bob@x", DisplayName: "Bob", Password: "password123",
	}))
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated && code != connect.CodePermissionDenied {
		t.Fatalf("anon create code = %v, want Unauthenticated/PermissionDenied", code)
	}

	created, err := c.CreateUser(ctx, withToken(connect.NewRequest(&identityv1.CreateUserRequest{
		Email: "bob@x", DisplayName: "Bob", Password: "password123",
	}), tok))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Msg.User.Email != "bob@x" {
		t.Fatalf("created: %+v", created.Msg)
	}

	got, err := c.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: created.Msg.User.Id}), tok))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Msg.User.Id != created.Msg.User.Id {
		t.Fatalf("get mismatch")
	}

	_, err = c.GetUser(ctx, withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: "00000000-0000-0000-0000-000000000000"}), tok))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("get unknown code = %v, want NotFound", connect.CodeOf(err))
	}

	list, err := c.ListUsers(ctx, withToken(connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 50}), tok))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Msg.Users) < 2 {
		t.Fatalf("list returned %d users, want >=2", len(list.Msg.Users))
	}
}

func TestGetUserMalformedUUID(t *testing.T) {
	pool, url := newServer(t)
	seedUser(t, pool, "admin@x", "supersecret", true)
	tok := adminToken(t, url)
	c := identityv1connect.NewIdentityServiceClient(http.DefaultClient, url)
	_, err := c.GetUser(context.Background(), withToken(connect.NewRequest(&identityv1.GetUserRequest{Id: "not-a-uuid"}), tok))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("malformed uuid code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}
