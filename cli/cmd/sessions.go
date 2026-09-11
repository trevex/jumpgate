package cmd

import (
	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
)

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "Manage your login sessions",
}

var sessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your active sessions",
	Args:  cobra.NoArgs,
	RunE:  runSessionsList,
}

var sessionsRevokeCmd = &cobra.Command{
	Use:   "revoke <session-id>",
	Short: "Revoke one of your sessions",
	Args:  cobra.ExactArgs(1),
	RunE:  runSessionsRevoke,
}

var sessionsRevokeAllKeepCurrent bool

var sessionsRevokeAllCmd = &cobra.Command{
	Use:   "revoke-all",
	Short: "Log out of all your sessions",
	Args:  cobra.NoArgs,
	RunE:  runSessionsRevokeAll,
}

func init() {
	sessionsRevokeAllCmd.Flags().BoolVar(&sessionsRevokeAllKeepCurrent, "keep-current", false, "keep the current session active")
	sessionsCmd.AddCommand(sessionsListCmd, sessionsRevokeCmd, sessionsRevokeAllCmd)
	rootCmd.AddCommand(sessionsCmd)
}

func runSessionsList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&authv1.ListSessionsRequest{})
	cl.Authorize(req)
	resp, err := cl.Auth().ListSessions(cmd.Context(), req)
	if err != nil {
		return err
	}

	sessions := resp.Msg.GetSessions()
	rows := make([][]string, 0, len(sessions))
	msgs := make([]proto.Message, 0, len(sessions))
	for _, s := range sessions {
		cur := ""
		if s.GetCurrent() {
			cur = "*"
		}
		rows = append(rows, []string{
			s.GetId(), s.GetLabel(), s.GetClientIp(), s.GetUserAgent(),
			s.GetLastUsedAt().AsTime().Format("2006-01-02 15:04"),
			s.GetExpiresAt().AsTime().Format("2006-01-02 15:04"),
			cur,
		})
		msgs = append(msgs, s)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: []string{"ID", "LABEL", "IP", "AGENT", "LAST USED", "EXPIRES", "CURRENT"},
		Rows:    rows,
	})
}

func runSessionsRevoke(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&authv1.RevokeSessionRequest{Id: args[0]})
	cl.Authorize(req)
	_, err = cl.Auth().RevokeSession(cmd.Context(), req)
	return err
}

func runSessionsRevokeAll(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&authv1.RevokeAllSessionsRequest{ExceptCurrent: sessionsRevokeAllKeepCurrent})
	cl.Authorize(req)
	_, err = cl.Auth().RevokeAllSessions(cmd.Context(), req)
	return err
}
