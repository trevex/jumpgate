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

var (
	foldersListCascade bool
)

var foldersListCmd = &cobra.Command{
	Use:   "list [parent]",
	Short: "List folders",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runFoldersList,
}

func init() {
	foldersCreateCmd.Flags().StringVar(&foldersCreateParent, "parent", "", "parent folder ID")

	foldersListCmd.Flags().BoolVar(&foldersListCascade, "cascade", false, "include folders in all descendant levels")

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

func runFoldersList(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	parent := ""
	if len(args) > 0 {
		parent = args[0]
	}

	folders, err := collectPages(func(token string) ([]*catalogv1.Folder, string, error) {
		req := connect.NewRequest(&catalogv1.ListFoldersRequest{
			Parent:    parent,
			Cascade:   foldersListCascade,
			PageSize:  100,
			PageToken: token,
		})
		cl.Authorize(req)
		resp, err := cl.Catalog().ListFolders(cmd.Context(), req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetFolders(), resp.Msg.GetNextPageToken(), nil
	})
	if err != nil {
		return err
	}

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
