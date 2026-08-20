package cmd

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/cli/internal/wardenclient"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
)

// resolveUserID returns s unchanged if it is already a UUID; otherwise it resolves
// a user by email via warden's ResolveUser (admin only).
func resolveUserID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}
	req := connect.NewRequest(&identityv1.ResolveUserRequest{Email: s})
	cl.Authorize(req)
	resp, err := cl.Identity().ResolveUser(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Msg.GetUserId(), nil
}

// resolveGroupID returns s unchanged if it is already a UUID; otherwise it resolves
// a group by name via warden's ResolveGroup (admin only).
func resolveGroupID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}
	req := connect.NewRequest(&identityv1.ResolveGroupRequest{Name: s})
	cl.Authorize(req)
	resp, err := cl.Identity().ResolveGroup(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Msg.GetGroupId(), nil
}

// resolveRoleID maps a uuid | name | <role>.<folder-path> to a role id via warden's
// ResolveRole (admin only). A uuid short-circuits locally (no round-trip).
func resolveRoleID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}
	req := connect.NewRequest(&accessv1.ResolveRoleRequest{Ref: s})
	cl.Authorize(req)
	resp, err := cl.Access().ResolveRole(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Msg.GetRoleId(), nil
}

// resolveFolderID maps a uuid or DNS-style folder path to a folder id via warden's
// ResolveFolder (admin only). A uuid short-circuits locally (no round-trip).
func resolveFolderID(ctx context.Context, cl *wardenclient.Client, s string) (string, error) {
	if _, err := uuid.Parse(s); err == nil {
		return s, nil
	}
	req := connect.NewRequest(&catalogv1.ResolveFolderRequest{Ref: s})
	cl.Authorize(req)
	resp, err := cl.Catalog().ResolveFolder(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Msg.GetFolderId(), nil
}
