package cmd

import (
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
)

var assetHeaders = []string{"ID", "NAME", "KIND", "FOLDER"}

func assetRow(a *catalogv1.Asset) []string {
	return []string{a.GetId(), a.GetName(), a.GetKind(), a.GetFolderId()}
}

var visibleAssetHeaders = []string{"ID", "NAME", "ACTIVE"}

func visibleAssetRow(a *catalogv1.VisibleAsset) []string {
	return []string{a.GetId(), a.GetName(), fmt.Sprintf("%t", a.GetActive())}
}

var assetsCmd = &cobra.Command{
	Use:   "assets",
	Short: "Manage assets",
}

var assetsOnboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Onboard an asset",
}

var (
	onboardSSHFolder  string
	onboardSSHTarget  string
	onboardSSHLogins  []string
	onboardSSHHostKey string
	onboardSSHAuth    string
)

var assetsOnboardSSHCmd = &cobra.Command{
	Use:   "ssh <name>",
	Short: "Onboard an SSH asset and set its config in one step",
	Args:  cobra.ExactArgs(1),
	RunE:  runAssetsOnboardSSH,
}

var assetsListFolder string

var assetsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List assets",
	Args:  cobra.NoArgs,
	RunE:  runAssetsList,
}

var assetsGetCmd = &cobra.Command{
	Use:   "get <asset>",
	Short: "Show access info for an asset",
	Args:  cobra.ExactArgs(1),
	RunE:  runAssetsGet,
}

func init() {
	assetsOnboardSSHCmd.Flags().StringVar(&onboardSSHFolder, "folder", "", "folder id or name (required)")
	assetsOnboardSSHCmd.Flags().StringVar(&onboardSSHTarget, "target", "", "target host:port")
	assetsOnboardSSHCmd.Flags().StringSliceVar(&onboardSSHLogins, "login", nil, "allowed login (repeatable or comma-separated)")
	assetsOnboardSSHCmd.Flags().StringVar(&onboardSSHHostKey, "host-key", "", "target host public key (authorized_keys line)")
	assetsOnboardSSHCmd.Flags().StringVar(&onboardSSHAuth, "auth", "ca-cert", "auth method")
	_ = assetsOnboardSSHCmd.MarkFlagRequired("folder")

	assetsOnboardCmd.AddCommand(assetsOnboardSSHCmd)

	assetsListCmd.Flags().StringVar(&assetsListFolder, "folder", "", "folder id or name; lists assets in that folder")

	assetsCmd.AddCommand(assetsOnboardCmd)
	assetsCmd.AddCommand(assetsListCmd)
	assetsCmd.AddCommand(assetsGetCmd)
	rootCmd.AddCommand(assetsCmd)
}

func runAssetsOnboardSSH(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, onboardSSHFolder)
	if err != nil {
		return err
	}

	createReq := connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     args[0],
		Kind:     "ssh",
	})
	cl.Authorize(createReq)
	createResp, err := cl.Catalog().CreateAsset(cmd.Context(), createReq)
	if err != nil {
		return err
	}
	asset := createResp.Msg.GetAsset()

	cfgReq := connect.NewRequest(&vaultv1.SetSSHAssetConfigRequest{
		AssetId:       asset.GetId(),
		AllowedLogins: onboardSSHLogins,
		AuthMethod:    onboardSSHAuth,
		HostPublicKey: onboardSSHHostKey,
		TargetAddress: onboardSSHTarget,
	})
	cl.Authorize(cfgReq)
	if _, err := cl.Vault().SetSSHAssetConfig(cmd.Context(), cfgReq); err != nil {
		// The asset now exists but is unconfigured. Surface its id so the user
		// can retry only the config step rather than re-create a duplicate.
		return fmt.Errorf("asset %q was created (id %s) but setting its SSH config failed: %w", asset.GetName(), asset.GetId(), err)
	}

	return output.RenderProto(cmd.OutOrStdout(), flagOutput, asset, &output.Table{
		Headers: assetHeaders,
		Rows:    [][]string{assetRow(asset)},
	})
}

func runAssetsList(cmd *cobra.Command, _ []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	if cmd.Flags().Changed("folder") {
		folderID, err := resolveFolderID(cmd.Context(), cl, assetsListFolder)
		if err != nil {
			return err
		}
		req := connect.NewRequest(&catalogv1.ListAssetsByFolderRequest{FolderId: folderID})
		cl.Authorize(req)
		resp, err := cl.Catalog().ListAssetsByFolder(cmd.Context(), req)
		if err != nil {
			return err
		}
		assets := resp.Msg.GetAssets()
		rows := make([][]string, 0, len(assets))
		msgs := make([]proto.Message, 0, len(assets))
		for _, a := range assets {
			rows = append(rows, assetRow(a))
			msgs = append(msgs, a)
		}
		return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
			Headers: assetHeaders,
			Rows:    rows,
		})
	}

	req := connect.NewRequest(&catalogv1.ListVisibleAssetsRequest{})
	cl.Authorize(req)
	resp, err := cl.Catalog().ListVisibleAssets(cmd.Context(), req)
	if err != nil {
		return err
	}
	assets := resp.Msg.GetAssets()
	rows := make([][]string, 0, len(assets))
	msgs := make([]proto.Message, 0, len(assets))
	for _, a := range assets {
		rows = append(rows, visibleAssetRow(a))
		msgs = append(msgs, a)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: visibleAssetHeaders,
		Rows:    rows,
	})
}

func runAssetsGet(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	assetID, err := cl.ResolveAsset(cmd.Context(), args[0])
	if err != nil {
		return err
	}

	req := connect.NewRequest(&catalogv1.GetAssetAccessRequest{AssetId: assetID})
	cl.Authorize(req)
	resp, err := cl.Catalog().GetAssetAccess(cmd.Context(), req)
	if err != nil {
		return err
	}

	access := resp.Msg
	return output.RenderProto(cmd.OutOrStdout(), flagOutput, access, &output.Table{
		Headers: []string{"ACTIVE ROLES", "REQUESTABLE ROLES"},
		Rows: [][]string{{
			strings.Join(access.GetActiveRoleIds(), ", "),
			strings.Join(access.GetRequestableRoleIds(), ", "),
		}},
	})
}
