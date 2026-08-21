package cmd

import (
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
)

var roleHeaders = []string{"ID", "NAME", "FOLDER", "CAPABILITIES"}

func roleRow(r *accessv1.Role) []string {
	folder := r.GetFolderPath()
	if folder == "" {
		folder = "global"
	}
	return []string{r.GetId(), r.GetName(), folder, strings.Join(r.GetCapabilities(), ", ")}
}

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Manage roles",
}

var (
	rolesCreateCapabilities []string
	rolesCreateFolder       string
)

var rolesCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a role",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesCreate,
}

var (
	rolesListCascade bool
)

var rolesListCmd = &cobra.Command{
	Use:   "list [parent]",
	Short: "List roles",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRolesList,
}

func init() {
	rolesCreateCmd.Flags().StringSliceVar(&rolesCreateCapabilities, "capability", nil, "capability, e.g. ssh:login:deploy (repeatable or comma-separated)")
	rolesCreateCmd.Flags().StringVar(&rolesCreateFolder, "folder", "", "folder to scope the role to (uuid or DNS path); empty = global")

	rolesListCmd.Flags().BoolVar(&rolesListCascade, "cascade", false, "list roles in the whole subtree")

	rolesCmd.AddCommand(rolesCreateCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rootCmd.AddCommand(rolesCmd)
}

func runRolesCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	var folderID string
	if rolesCreateFolder != "" {
		folderID, err = resolveFolderID(cmd.Context(), cl, rolesCreateFolder)
		if err != nil {
			return err
		}
	}

	req := connect.NewRequest(&accessv1.CreateRoleRequest{
		Name:         args[0],
		FolderId:     folderID,
		Capabilities: rolesCreateCapabilities,
	})
	cl.Authorize(req)
	resp, err := cl.Access().CreateRole(cmd.Context(), req)
	if err != nil {
		return err
	}

	r := resp.Msg.GetRole()
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, r, &output.Table{
		Headers: roleHeaders,
		Rows:    [][]string{roleRow(r)},
	})
}

func runRolesList(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	parent := ""
	if len(args) > 0 {
		parent = args[0]
	}

	roles, err := collectPages(func(token string) ([]*accessv1.Role, string, error) {
		req := connect.NewRequest(&accessv1.ListRolesRequest{
			Parent:    parent,
			Cascade:   rolesListCascade,
			PageSize:  100,
			PageToken: token,
		})
		cl.Authorize(req)
		resp, err := cl.Access().ListRoles(cmd.Context(), req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetRoles(), resp.Msg.GetNextPageToken(), nil
	})
	if err != nil {
		return err
	}

	rows := make([][]string, 0, len(roles))
	msgs := make([]proto.Message, 0, len(roles))
	for _, r := range roles {
		rows = append(rows, roleRow(r))
		msgs = append(msgs, r)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: roleHeaders,
		Rows:    rows,
	})
}
