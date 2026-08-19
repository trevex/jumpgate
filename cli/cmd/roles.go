package cmd

import (
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	accessv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1"
)

var roleHeaders = []string{"ID", "NAME", "RESOURCE TYPE", "CAPABILITIES"}

func roleRow(r *accessv1.Role) []string {
	return []string{r.GetId(), r.GetName(), r.GetResourceType(), strings.Join(r.GetCapabilities(), ", ")}
}

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Manage roles",
}

var (
	rolesCreateResourceType string
	rolesCreateCapabilities []string
)

var rolesCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a role",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesCreate,
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles",
	Args:  cobra.NoArgs,
	RunE:  runRolesList,
}

func init() {
	rolesCreateCmd.Flags().StringVar(&rolesCreateResourceType, "resource-type", "asset", "resource type the role applies to")
	rolesCreateCmd.Flags().StringSliceVar(&rolesCreateCapabilities, "capability", nil, "capability, e.g. ssh:login:deploy (repeatable or comma-separated)")

	rolesCmd.AddCommand(rolesCreateCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rootCmd.AddCommand(rolesCmd)
}

func runRolesCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&accessv1.CreateRoleRequest{
		Name:         args[0],
		ResourceType: rolesCreateResourceType,
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

func runRolesList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&accessv1.ListRolesRequest{PageSize: 100})
	cl.Authorize(req)
	resp, err := cl.Access().ListRoles(cmd.Context(), req)
	if err != nil {
		return err
	}

	roles := resp.Msg.GetRoles()
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
