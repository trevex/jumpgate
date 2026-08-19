package cmd

import (
	"fmt"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
)

var groupHeaders = []string{"ID", "NAME"}

func groupRow(g *identityv1.Group) []string {
	return []string{g.GetId(), g.GetName()}
}

var groupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Manage groups",
}

var groupsCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a group",
	Args:  cobra.ExactArgs(1),
	RunE:  runGroupsCreate,
}

var groupsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups",
	Args:  cobra.NoArgs,
	RunE:  runGroupsList,
}

var groupsAddMemberCmd = &cobra.Command{
	Use:   "add-member <group> <user>",
	Short: "Add a user to a group",
	Args:  cobra.ExactArgs(2),
	RunE:  runGroupsAddMember,
}

var groupsRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member <group> <user>",
	Short: "Remove a user from a group",
	Args:  cobra.ExactArgs(2),
	RunE:  runGroupsRemoveMember,
}

func init() {
	groupsCmd.AddCommand(groupsCreateCmd)
	groupsCmd.AddCommand(groupsListCmd)
	groupsCmd.AddCommand(groupsAddMemberCmd)
	groupsCmd.AddCommand(groupsRemoveMemberCmd)
	rootCmd.AddCommand(groupsCmd)
}

func runGroupsCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&identityv1.CreateGroupRequest{Name: args[0]})
	cl.Authorize(req)
	resp, err := cl.Identity().CreateGroup(cmd.Context(), req)
	if err != nil {
		return err
	}

	g := resp.Msg.GetGroup()
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, g, &output.Table{
		Headers: groupHeaders,
		Rows:    [][]string{groupRow(g)},
	})
}

func runGroupsList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&identityv1.ListGroupsRequest{PageSize: 100})
	cl.Authorize(req)
	resp, err := cl.Identity().ListGroups(cmd.Context(), req)
	if err != nil {
		return err
	}

	groups := resp.Msg.GetGroups()
	rows := make([][]string, 0, len(groups))
	msgs := make([]proto.Message, 0, len(groups))
	for _, g := range groups {
		rows = append(rows, groupRow(g))
		msgs = append(msgs, g)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: groupHeaders,
		Rows:    rows,
	})
}

func runGroupsAddMember(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	groupID, err := resolveGroupID(cmd.Context(), cl, args[0])
	if err != nil {
		return err
	}
	userID, err := resolveUserID(cmd.Context(), cl, args[1])
	if err != nil {
		return err
	}

	req := connect.NewRequest(&identityv1.AddUserToGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	})
	cl.Authorize(req)
	if _, err := cl.Identity().AddUserToGroup(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "added user %s to group %s\n", userID, groupID)
	return nil
}

func runGroupsRemoveMember(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	groupID, err := resolveGroupID(cmd.Context(), cl, args[0])
	if err != nil {
		return err
	}
	userID, err := resolveUserID(cmd.Context(), cl, args[1])
	if err != nil {
		return err
	}

	req := connect.NewRequest(&identityv1.RemoveUserFromGroupRequest{
		GroupId: groupID,
		UserId:  userID,
	})
	cl.Authorize(req)
	if _, err := cl.Identity().RemoveUserFromGroup(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed user %s from group %s\n", userID, groupID)
	return nil
}
