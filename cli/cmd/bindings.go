package cmd

import (
	"fmt"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
)

var bindingHeaders = []string{"ID", "ROLE", "SUBJECT", "SCOPE"}

func bindingRow(b *accessv1.RoleBinding) []string {
	return []string{b.GetId(), b.GetRoleId(), bindingSubject(b), bindingScope(b)}
}

// bindingSubject renders the single subject of a binding as a "kind:id" pair.
func bindingSubject(b *accessv1.RoleBinding) string {
	switch {
	case b.GetSubjectUserId() != "":
		return "user:" + b.GetSubjectUserId()
	case b.GetSubjectGroupId() != "":
		return "group:" + b.GetSubjectGroupId()
	default:
		return ""
	}
}

// bindingScope renders the single scope of a binding as a "kind:id" pair.
func bindingScope(b *accessv1.RoleBinding) string {
	switch {
	case b.GetScopeAssetId() != "":
		return "asset:" + b.GetScopeAssetId()
	case b.GetScopeFolderId() != "":
		return "folder:" + b.GetScopeFolderId()
	default:
		return ""
	}
}

var bindingsCmd = &cobra.Command{
	Use:   "bindings",
	Short: "Manage standing role bindings",
}

var (
	bindingsCreateRole   string
	bindingsCreateUser   string
	bindingsCreateGroup  string
	bindingsCreateAsset  string
	bindingsCreateFolder string
)

var bindingsCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Grant a role to a subject at a scope",
	Args:  cobra.NoArgs,
	RunE:  runBindingsCreate,
}

var (
	bindingsListUser  string
	bindingsListAsset string
)

var bindingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List role bindings",
	Args:  cobra.NoArgs,
	RunE:  runBindingsList,
}

var bindingsDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a role binding",
	Args:  cobra.ExactArgs(1),
	RunE:  runBindingsDelete,
}

func init() {
	bindingsCreateCmd.Flags().StringVar(&bindingsCreateRole, "role", "", "role id or name (required)")
	bindingsCreateCmd.Flags().StringVar(&bindingsCreateUser, "user", "", "subject user id or email")
	bindingsCreateCmd.Flags().StringVar(&bindingsCreateGroup, "group", "", "subject group id or name")
	bindingsCreateCmd.Flags().StringVar(&bindingsCreateAsset, "asset", "", "scope asset id or name")
	bindingsCreateCmd.Flags().StringVar(&bindingsCreateFolder, "folder", "", "scope folder id or name")
	_ = bindingsCreateCmd.MarkFlagRequired("role")

	bindingsListCmd.Flags().StringVar(&bindingsListUser, "user", "", "filter by subject user id or email")
	bindingsListCmd.Flags().StringVar(&bindingsListAsset, "asset", "", "filter by scope asset id or name")

	bindingsCmd.AddCommand(bindingsCreateCmd)
	bindingsCmd.AddCommand(bindingsListCmd)
	bindingsCmd.AddCommand(bindingsDeleteCmd)
	rootCmd.AddCommand(bindingsCmd)
}

func runBindingsCreate(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	// Exactly one subject and exactly one scope. Bindings are (role, subject,
	// scope) triples; warden rejects anything else, but we fail early with a
	// clearer message than a server-side validation error.
	if (bindingsCreateUser != "") == (bindingsCreateGroup != "") {
		return fmt.Errorf("exactly one of --user or --group is required")
	}
	if (bindingsCreateAsset != "") == (bindingsCreateFolder != "") {
		return fmt.Errorf("exactly one of --asset or --folder is required")
	}

	roleID, err := resolveRoleID(cmd.Context(), cl, bindingsCreateRole)
	if err != nil {
		return err
	}

	req := &accessv1.CreateRoleBindingRequest{RoleId: roleID}

	if bindingsCreateUser != "" {
		userID, err := resolveUserID(cmd.Context(), cl, bindingsCreateUser)
		if err != nil {
			return err
		}
		req.SubjectUserId = userID
	} else {
		groupID, err := resolveGroupID(cmd.Context(), cl, bindingsCreateGroup)
		if err != nil {
			return err
		}
		req.SubjectGroupId = groupID
	}

	if bindingsCreateAsset != "" {
		assetID, err := cl.ResolveAsset(cmd.Context(), bindingsCreateAsset)
		if err != nil {
			return err
		}
		req.ScopeAssetId = assetID
	} else {
		folderID, err := resolveFolderID(cmd.Context(), cl, bindingsCreateFolder)
		if err != nil {
			return err
		}
		req.ScopeFolderId = folderID
	}

	creq := connect.NewRequest(req)
	cl.Authorize(creq)
	resp, err := cl.Access().CreateRoleBinding(cmd.Context(), creq)
	if err != nil {
		return err
	}

	// The response carries only the new id; echo it alongside the resolved
	// triple so json output is self-describing.
	b := &accessv1.RoleBinding{
		Id:             resp.Msg.GetId(),
		RoleId:         req.GetRoleId(),
		ScopeFolderId:  req.GetScopeFolderId(),
		ScopeAssetId:   req.GetScopeAssetId(),
		SubjectUserId:  req.GetSubjectUserId(),
		SubjectGroupId: req.GetSubjectGroupId(),
	}
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, b, &output.Table{
		Headers: bindingHeaders,
		Rows:    [][]string{bindingRow(b)},
	})
}

func runBindingsList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := &accessv1.ListRoleBindingsRequest{}
	if bindingsListUser != "" {
		userID, err := resolveUserID(cmd.Context(), cl, bindingsListUser)
		if err != nil {
			return err
		}
		req.SubjectUserId = userID
	}
	if bindingsListAsset != "" {
		assetID, err := cl.ResolveAsset(cmd.Context(), bindingsListAsset)
		if err != nil {
			return err
		}
		req.ScopeAssetId = assetID
	}

	lreq := connect.NewRequest(req)
	cl.Authorize(lreq)
	resp, err := cl.Access().ListRoleBindings(cmd.Context(), lreq)
	if err != nil {
		return err
	}

	bindings := resp.Msg.GetBindings()
	rows := make([][]string, 0, len(bindings))
	msgs := make([]proto.Message, 0, len(bindings))
	for _, b := range bindings {
		rows = append(rows, bindingRow(b))
		msgs = append(msgs, b)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: bindingHeaders,
		Rows:    rows,
	})
}

func runBindingsDelete(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&accessv1.DeleteRoleBindingRequest{Id: args[0]})
	cl.Authorize(req)
	if _, err := cl.Access().DeleteRoleBinding(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "deleted binding %s\n", args[0])
	return nil
}
