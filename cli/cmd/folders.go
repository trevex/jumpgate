package cmd

import (
	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

var folderHeaders = []string{"ID", "NAME", "PARENT", "PATH"}

func folderRow(f *catalogv1.Folder) []string {
	return []string{f.GetId(), f.GetName(), f.GetParentId(), f.GetPath()}
}

var foldersCmd = &cobra.Command{
	Use:   "folders",
	Short: "Manage folders",
}

var foldersCreateParent string

var foldersCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a folder",
	Args:  cobra.ExactArgs(1),
	RunE:  runFoldersCreate,
}

var foldersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List folders",
	Args:  cobra.NoArgs,
	RunE:  runFoldersList,
}

func init() {
	foldersCreateCmd.Flags().StringVar(&foldersCreateParent, "parent", "", "parent folder ID")

	foldersCmd.AddCommand(foldersCreateCmd)
	foldersCmd.AddCommand(foldersListCmd)
	rootCmd.AddCommand(foldersCmd)
}

func runFoldersCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	msg := &catalogv1.CreateFolderRequest{Name: args[0]}
	if cmd.Flags().Changed("parent") {
		msg.ParentId = foldersCreateParent
	}

	req := connect.NewRequest(msg)
	cl.Authorize(req)
	resp, err := cl.Catalog().CreateFolder(cmd.Context(), req)
	if err != nil {
		return err
	}

	f := resp.Msg.GetFolder()
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, f, &output.Table{
		Headers: folderHeaders,
		Rows:    [][]string{folderRow(f)},
	})
}

func runFoldersList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	req := connect.NewRequest(&catalogv1.ListFoldersRequest{PageSize: 100})
	cl.Authorize(req)
	resp, err := cl.Catalog().ListFolders(cmd.Context(), req)
	if err != nil {
		return err
	}

	folders := resp.Msg.GetFolders()
	rows := make([][]string, 0, len(folders))
	msgs := make([]proto.Message, 0, len(folders))
	for _, f := range folders {
		rows = append(rows, folderRow(f))
		msgs = append(msgs, f)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: folderHeaders,
		Rows:    rows,
	})
}
