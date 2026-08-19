package cmd

import (
	"fmt"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	identityv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1"
)

var userHeaders = []string{"ID", "EMAIL", "NAME", "ADMIN"}

func userRow(u *identityv1.User) []string {
	return []string{u.GetId(), u.GetEmail(), u.GetDisplayName(), fmt.Sprintf("%t", u.GetIsAdmin())}
}

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Manage users",
}

var (
	usersCreateName     string
	usersCreateAdmin    bool
	usersCreatePassword string
)

var usersCreateCmd = &cobra.Command{
	Use:   "create <email>",
	Short: "Create a user",
	Args:  cobra.ExactArgs(1),
	RunE:  runUsersCreate,
}

var usersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	Args:  cobra.NoArgs,
	RunE:  runUsersList,
}

func init() {
	usersCreateCmd.Flags().StringVar(&usersCreateName, "name", "", "display name")
	usersCreateCmd.Flags().BoolVar(&usersCreateAdmin, "admin", false, "grant admin privileges")
	usersCreateCmd.Flags().StringVar(&usersCreatePassword, "password", "", "initial login password (min 8 chars)")

	usersCmd.AddCommand(usersCreateCmd)
	usersCmd.AddCommand(usersListCmd)
	rootCmd.AddCommand(usersCmd)
}

func runUsersCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&identityv1.CreateUserRequest{
		Email:       args[0],
		DisplayName: usersCreateName,
		IsAdmin:     usersCreateAdmin,
		Password:    usersCreatePassword,
	})
	cl.Authorize(req)
	resp, err := cl.Identity().CreateUser(cmd.Context(), req)
	if err != nil {
		return err
	}

	u := resp.Msg.GetUser()
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, u, &output.Table{
		Headers: userHeaders,
		Rows:    [][]string{userRow(u)},
	})
}

func runUsersList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&identityv1.ListUsersRequest{PageSize: 100})
	cl.Authorize(req)
	resp, err := cl.Identity().ListUsers(cmd.Context(), req)
	if err != nil {
		return err
	}

	users := resp.Msg.GetUsers()
	rows := make([][]string, 0, len(users))
	msgs := make([]proto.Message, 0, len(users))
	for _, u := range users {
		rows = append(rows, userRow(u))
		msgs = append(msgs, u)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: userHeaders,
		Rows:    rows,
	})
}
