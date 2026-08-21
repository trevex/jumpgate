package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
)

type stubGroups struct {
	stubIdentity
	gotCreateGroup  *identityv1.CreateGroupRequest
	gotResolveGroup *identityv1.ResolveGroupRequest
	gotAddMember    *identityv1.AddUserToGroupRequest
	gotRemove       *identityv1.RemoveUserFromGroupRequest
}

func (s *stubGroups) CreateGroup(_ context.Context, req *connect.Request[identityv1.CreateGroupRequest]) (*connect.Response[identityv1.CreateGroupResponse], error) {
	s.gotCreateGroup = req.Msg
	return connect.NewResponse(&identityv1.CreateGroupResponse{Group: &identityv1.Group{
		Id:   "g1",
		Name: req.Msg.GetName(),
	}}), nil
}

func (s *stubGroups) ListGroups(_ context.Context, _ *connect.Request[identityv1.ListGroupsRequest]) (*connect.Response[identityv1.ListGroupsResponse], error) {
	return connect.NewResponse(&identityv1.ListGroupsResponse{Groups: []*identityv1.Group{
		{Id: "11111111-1111-1111-1111-111111111111", Name: "eng", FolderPath: "team.prod"},
	}}), nil
}

func (s *stubGroups) ResolveGroup(_ context.Context, req *connect.Request[identityv1.ResolveGroupRequest]) (*connect.Response[identityv1.ResolveGroupResponse], error) {
	s.gotResolveGroup = req.Msg
	return connect.NewResponse(&identityv1.ResolveGroupResponse{GroupId: "11111111-1111-1111-1111-111111111111"}), nil
}

func (s *stubGroups) ResolveUser(_ context.Context, _ *connect.Request[identityv1.ResolveUserRequest]) (*connect.Response[identityv1.ResolveUserResponse], error) {
	return connect.NewResponse(&identityv1.ResolveUserResponse{UserId: "22222222-2222-2222-2222-222222222222"}), nil
}

func (s *stubGroups) AddUserToGroup(_ context.Context, req *connect.Request[identityv1.AddUserToGroupRequest]) (*connect.Response[identityv1.AddUserToGroupResponse], error) {
	s.gotAddMember = req.Msg
	return connect.NewResponse(&identityv1.AddUserToGroupResponse{}), nil
}

func (s *stubGroups) RemoveUserFromGroup(_ context.Context, req *connect.Request[identityv1.RemoveUserFromGroupRequest]) (*connect.Response[identityv1.RemoveUserFromGroupResponse], error) {
	s.gotRemove = req.Msg
	return connect.NewResponse(&identityv1.RemoveUserFromGroupResponse{}), nil
}

func TestGroupsCreate(t *testing.T) {
	s := &stubGroups{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"groups", "create", "eng", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreateGroup.GetName() != "eng" {
		t.Fatalf("req=%+v", s.gotCreateGroup)
	}
	if !strings.Contains(out.String(), "g1") {
		t.Fatalf("out=%s", out.String())
	}
}

func TestGroupsCreateFolder(t *testing.T) {
	s := &stubGroups{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table"; groupsCreateFolder = "" })

	const folderUUID = "33333333-3333-3333-3333-333333333333"

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	// A uuid --folder short-circuits resolveFolderID (no catalog round-trip).
	rootCmd.SetArgs([]string{"groups", "create", "sre", "--folder", folderUUID, "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotCreateGroup == nil {
		t.Fatalf("CreateGroup not called")
	}
	if s.gotCreateGroup.GetName() != "sre" || s.gotCreateGroup.GetFolderId() != folderUUID {
		t.Fatalf("req=%+v", s.gotCreateGroup)
	}
}

func TestGroupsList(t *testing.T) {
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, &stubGroups{}))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"groups", "list", "-o", "table"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "eng") || !strings.Contains(got, "11111111") {
		t.Fatalf("out=%s", got)
	}
	// FOLDER column renders the group's folder_path.
	if !strings.Contains(got, "FOLDER") || !strings.Contains(got, "team.prod") {
		t.Fatalf("missing FOLDER column: out=%s", got)
	}
}

func TestGroupsAddMemberResolvesNames(t *testing.T) {
	s := &stubGroups{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	// Both args are names/emails, not UUIDs: must be resolved before the RPC.
	// The group ref uses the <group>@<folder-path> form: the CLI passes it through
	// verbatim to ResolveGroup (server-side parsing).
	rootCmd.SetArgs([]string{"groups", "add-member", "sre@team", "alice@x"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotResolveGroup == nil || s.gotResolveGroup.GetName() != "sre@team" {
		t.Fatalf("ResolveGroup ref=%+v", s.gotResolveGroup)
	}
	if s.gotAddMember == nil {
		t.Fatalf("AddUserToGroup not called")
	}
	if s.gotAddMember.GetGroupId() != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("group_id=%q", s.gotAddMember.GetGroupId())
	}
	if s.gotAddMember.GetUserId() != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("user_id=%q", s.gotAddMember.GetUserId())
	}
}

func TestGroupsRemoveMemberResolvesNames(t *testing.T) {
	s := &stubGroups{}
	t.Setenv("JUMPGATE_WARDEN_ADDR", newIdentityStub(t, s))
	t.Setenv("JUMPGATE_TOKEN", "tok")
	t.Cleanup(func() { flagOutput = "table" })

	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"groups", "remove-member", "eng", "alice@x"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if s.gotRemove == nil {
		t.Fatalf("RemoveUserFromGroup not called")
	}
	if s.gotRemove.GetGroupId() != "11111111-1111-1111-1111-111111111111" ||
		s.gotRemove.GetUserId() != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("req=%+v", s.gotRemove)
	}
}
