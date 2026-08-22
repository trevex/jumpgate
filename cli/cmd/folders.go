package cmd

import (
	"fmt"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
)

// strPtr returns a pointer to s. It is used to populate optional (proto3
// optional / *string) request fields, where a nil pointer means "unchanged"
// and a non-nil pointer (even to "") means "set to this value".
func strPtr(s string) *string { return &s }

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

var foldersDeleteCmd = &cobra.Command{
	Use:   "delete <folder>",
	Short: "Delete a folder",
	Long: "Delete a folder. The folder must be empty; if it still contains " +
		"sub-folders or assets the server refuses and lists the blockers.",
	Args: cobra.ExactArgs(1),
	RunE: runFoldersDelete,
}

var foldersRenameCmd = &cobra.Command{
	Use:   "rename <folder> <new-name>",
	Short: "Rename a folder",
	Args:  cobra.ExactArgs(2),
	RunE:  runFoldersRename,
}

var foldersMoveRoot bool

var foldersMoveCmd = &cobra.Command{
	Use:   "move <folder> [new-parent]",
	Short: "Move a folder under a new parent (or to the root with --root)",
	Long: "Move a folder under a new parent folder. Pass the destination parent as " +
		"a folder id or DNS path, or use --root to move the folder to the top level.",
	Args: cobra.RangeArgs(1, 2),
	RunE: runFoldersMove,
}

func init() {
	foldersCreateCmd.Flags().StringVar(&foldersCreateParent, "parent", "", "parent folder ID")

	foldersListCmd.Flags().BoolVar(&foldersListCascade, "cascade", false, "include folders in all descendant levels")

	foldersMoveCmd.Flags().BoolVar(&foldersMoveRoot, "root", false, "move the folder to the root (no parent)")

	foldersCmd.AddCommand(foldersCreateCmd)
	foldersCmd.AddCommand(foldersListCmd)
	foldersCmd.AddCommand(foldersDeleteCmd)
	foldersCmd.AddCommand(foldersRenameCmd)
	foldersCmd.AddCommand(foldersMoveCmd)
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

func runFoldersDelete(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, args[0])
	if err != nil {
		return err
	}

	// A non-empty folder is refused by the server (FailedPrecondition); its error
	// message already lists the blocking sub-folders/assets, so return it as-is.
	req := connect.NewRequest(&catalogv1.DeleteFolderRequest{FolderId: folderID})
	cl.Authorize(req)
	if _, err := cl.Catalog().DeleteFolder(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "deleted folder %s\n", args[0])
	return nil
}

func runFoldersRename(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, args[0])
	if err != nil {
		return err
	}

	name := args[1]
	req := connect.NewRequest(&catalogv1.UpdateFolderRequest{FolderId: folderID, Name: &name})
	cl.Authorize(req)
	if _, err := cl.Catalog().UpdateFolder(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "renamed folder %s to %s\n", args[0], name)
	return nil
}

func runFoldersMove(cmd *cobra.Command, args []string) error {
	// Exactly one of --root or a <new-parent> arg selects the destination. A move
	// must always send a non-nil ParentId (nil means "unchanged").
	hasParentArg := len(args) > 1
	if foldersMoveRoot && hasParentArg {
		return fmt.Errorf("pass either --root or a new-parent, not both")
	}
	if !foldersMoveRoot && !hasParentArg {
		return fmt.Errorf("provide a new-parent folder or --root to move to the top level")
	}

	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, args[0])
	if err != nil {
		return err
	}

	// "" = root; a resolved id otherwise. Always a non-nil pointer so the server
	// treats it as a move.
	parentID := ""
	dest := "root"
	if hasParentArg {
		parentID, err = resolveFolderID(cmd.Context(), cl, args[1])
		if err != nil {
			return err
		}
		dest = args[1]
	}

	req := connect.NewRequest(&catalogv1.UpdateFolderRequest{FolderId: folderID, ParentId: strPtr(parentID)})
	cl.Authorize(req)
	if _, err := cl.Catalog().UpdateFolder(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "moved folder %s under %s\n", args[0], dest)
	return nil
}
