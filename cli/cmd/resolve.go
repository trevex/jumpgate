package cmd

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/cli/internal/wardenclient"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
)

// resolveUserID returns s unchanged if it is already a UUID; otherwise it looks
// up a user by email via ListUsers and returns the matching id. A missing or
// ambiguous match is a clear error.
func resolveUserID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}

	req := connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 1000})
	cl.Authorize(req)
	resp, err := cl.Identity().ListUsers(ctx, req)
	if err != nil {
		return "", err
	}

	var match string
	for _, u := range resp.Msg.GetUsers() {
		if u.GetEmail() == s {
			if match != "" {
				return "", fmt.Errorf("multiple users match email %q; use the user id", s)
			}
			match = u.GetId()
		}
	}
	if match == "" {
		return "", fmt.Errorf("no user found with email %q", s)
	}
	return match, nil
}

// resolveGroupID returns s unchanged if it is already a UUID; otherwise it looks
// up a group by name via ListGroups and returns the matching id. A missing or
// ambiguous match is a clear error.
func resolveGroupID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}

	req := connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 1000})
	cl.Authorize(req)
	resp, err := cl.Identity().ListGroups(ctx, req)
	if err != nil {
		return "", err
	}

	var match string
	for _, g := range resp.Msg.GetGroups() {
		if g.GetName() == s {
			if match != "" {
				return "", fmt.Errorf("multiple groups match name %q; use the group id", s)
			}
			match = g.GetId()
		}
	}
	if match == "" {
		return "", fmt.Errorf("no group found with name %q", s)
	}
	return match, nil
}

// resolveRoleID returns s unchanged if it is already a UUID; otherwise it looks
// up a role by name via ListRoles and returns the matching id. A missing or
// ambiguous match is a clear error.
func resolveRoleID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}

	req := connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 1000})
	cl.Authorize(req)
	resp, err := cl.Access().ListRoles(ctx, req)
	if err != nil {
		return "", err
	}

	var match string
	for _, r := range resp.Msg.GetRoles() {
		if r.GetName() == s {
			if match != "" {
				return "", fmt.Errorf("multiple roles match name %q; use the role id", s)
			}
			match = r.GetId()
		}
	}
	if match == "" {
		return "", fmt.Errorf("no role found with name %q", s)
	}
	return match, nil
}

// resolveFolderID returns s unchanged if it is already a UUID; otherwise it
// looks up a folder by name via ListFolders and returns the matching id. A
// missing or ambiguous match is a clear error.
func resolveFolderID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}

	req := connect.NewRequest(&catalogv1.ListFoldersRequest{PageSize: 1000})
	cl.Authorize(req)
	resp, err := cl.Catalog().ListFolders(ctx, req)
	if err != nil {
		return "", err
	}

	var match string
	for _, f := range resp.Msg.GetFolders() {
		if f.GetName() == s {
			if match != "" {
				return "", fmt.Errorf("multiple folders match name %q; use the folder id", s)
			}
			match = f.GetId()
		}
	}
	if match == "" {
		return "", fmt.Errorf("no folder found with name %q", s)
	}
	return match, nil
}
