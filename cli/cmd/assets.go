package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/trevex/jumpgate/cli/internal/output"
	"github.com/trevex/jumpgate/cli/internal/wardenclient"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	vaultv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1"
)

var assetHeaders = []string{"ID", "NAME", "KIND", "FOLDER", "PATH"}

func assetRow(a *catalogv1.Asset) []string {
	return []string{a.GetId(), a.GetName(), a.GetKind(), a.GetFolderId(), a.GetPath()}
}

var assetsCmd = &cobra.Command{
	Use:   "assets",
	Short: "Manage assets",
}

var assetsSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage SSH assets and their per-login auth",
}

var (
	sshCreateFolder  string
	sshCreateTarget  string
	sshCreateLogins  []string
	sshCreateHostKey string
)

var assetsSSHCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an SSH asset with its connection config",
	Long: "Create an SSH asset and its connection config in one call. Each --login " +
		"adds a ca (certificate) login with no secret; use `assets ssh login set` to " +
		"add password or key logins.",
	Args: cobra.ExactArgs(1),
	RunE: runAssetsSSHCreate,
}

var assetsSSHLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Manage the logins of an SSH asset",
}

var (
	sshLoginName    string
	sshLoginKind    string
	sshLoginStdin   bool
	sshLoginKeyFile string
)

var assetsSSHLoginSetCmd = &cobra.Command{
	Use:   "set <asset>",
	Short: "Add or replace a login on an SSH asset",
	Long: "Add or replace a login on an SSH asset. For --kind password the secret is " +
		"read from stdin (--password-stdin); for --kind key it is read from --key-file. " +
		"The secret is sealed in the vault and bound to the asset; ca logins carry no secret.",
	Args: cobra.ExactArgs(1),
	RunE: runAssetsSSHLoginSet,
}

var assetsSSHLoginListCmd = &cobra.Command{
	Use:   "list <asset>",
	Short: "List the logins of an SSH asset",
	Args:  cobra.ExactArgs(1),
	RunE:  runAssetsSSHLoginList,
}

var (
	assetsListParent  string
	assetsListCascade bool
)

var assetsListCmd = &cobra.Command{
	Use:   "list [parent]",
	Short: "List assets",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAssetsList,
}

var assetsGetCmd = &cobra.Command{
	Use:   "get <asset>",
	Short: "Show access info for an asset",
	Args:  cobra.ExactArgs(1),
	RunE:  runAssetsGet,
}

func init() {
	assetsSSHCreateCmd.Flags().StringVar(&sshCreateFolder, "folder", "", "folder id or name (required)")
	assetsSSHCreateCmd.Flags().StringVar(&sshCreateTarget, "target", "", "target host:port")
	assetsSSHCreateCmd.Flags().StringSliceVar(&sshCreateLogins, "login", nil, "ca login to allow (repeatable or comma-separated)")
	assetsSSHCreateCmd.Flags().StringVar(&sshCreateHostKey, "host-key", "", "target host public key (authorized_keys line)")
	_ = assetsSSHCreateCmd.MarkFlagRequired("folder")

	assetsSSHLoginSetCmd.Flags().StringVar(&sshLoginName, "login", "", "login name (required)")
	assetsSSHLoginSetCmd.Flags().StringVar(&sshLoginKind, "kind", "", "auth kind: ca|password|key (required)")
	assetsSSHLoginSetCmd.Flags().BoolVar(&sshLoginStdin, "password-stdin", false, "read the password from stdin (kind=password)")
	assetsSSHLoginSetCmd.Flags().StringVar(&sshLoginKeyFile, "key-file", "", "path to the private key file (kind=key)")
	_ = assetsSSHLoginSetCmd.MarkFlagRequired("login")
	_ = assetsSSHLoginSetCmd.MarkFlagRequired("kind")

	assetsSSHLoginCmd.AddCommand(assetsSSHLoginSetCmd)
	assetsSSHLoginCmd.AddCommand(assetsSSHLoginListCmd)

	assetsSSHCmd.AddCommand(assetsSSHCreateCmd)
	assetsSSHCmd.AddCommand(assetsSSHLoginCmd)

	assetsListCmd.Flags().BoolVar(&assetsListCascade, "cascade", false, "include assets in all descendant folders")

	assetsCmd.AddCommand(assetsSSHCmd)
	assetsCmd.AddCommand(assetsListCmd)
	assetsCmd.AddCommand(assetsGetCmd)
	rootCmd.AddCommand(assetsCmd)
}

var sshLoginHeaders = []string{"LOGIN", "KIND"}

func sshLoginRow(l *catalogv1.SSHLogin) []string {
	return []string{l.GetLogin(), l.GetKind()}
}

func runAssetsSSHCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, sshCreateFolder)
	if err != nil {
		return err
	}

	// Inline --login entries are ca-only: no secrets exist yet. Password/key
	// logins are added afterwards via `assets ssh login set`.
	logins := make([]*catalogv1.SSHLogin, 0, len(sshCreateLogins))
	for _, name := range sshCreateLogins {
		logins = append(logins, &catalogv1.SSHLogin{Login: name, Kind: "ca"})
	}

	// One call: the asset and its SSH config are created together, so there is no
	// window where a bare asset exists without config.
	createReq := connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     args[0],
		Kind:     "ssh",
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfig{
			Logins:        logins,
			HostPublicKey: sshCreateHostKey,
			TargetAddress: sshCreateTarget,
		}},
	})
	cl.Authorize(createReq)
	createResp, err := cl.Catalog().CreateAsset(cmd.Context(), createReq)
	if err != nil {
		return err
	}
	asset := createResp.Msg.GetAsset()

	return output.RenderProto(cmd.OutOrStdout(), flagOutput, asset, &output.Table{
		Headers: assetHeaders,
		Rows:    [][]string{assetRow(asset)},
	})
}

func runAssetsSSHLoginSet(cmd *cobra.Command, args []string) error {
	kind := sshLoginKind
	switch kind {
	case "ca", "password", "key":
	default:
		return fmt.Errorf("invalid --kind %q (want ca|password|key)", kind)
	}

	// Validate the secret source up front so we fail before any RPC.
	switch kind {
	case "ca":
		if sshLoginStdin {
			return fmt.Errorf("--password-stdin is only valid with --kind password")
		}
		if sshLoginKeyFile != "" {
			return fmt.Errorf("--key-file is only valid with --kind key")
		}
	case "password":
		if !sshLoginStdin {
			return fmt.Errorf("--kind password requires --password-stdin")
		}
		if sshLoginKeyFile != "" {
			return fmt.Errorf("--key-file is only valid with --kind key")
		}
	case "key":
		if sshLoginKeyFile == "" {
			return fmt.Errorf("--kind key requires --key-file")
		}
		if sshLoginStdin {
			return fmt.Errorf("--password-stdin is only valid with --kind password")
		}
	}

	cl, err := newClient()
	if err != nil {
		return err
	}

	assetID, err := cl.ResolveAsset(cmd.Context(), args[0])
	if err != nil {
		return err
	}

	// For password/key, seal the secret first and bind it to the asset; ca has
	// no secret.
	var secretID string
	switch kind {
	case "password":
		value, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		value = trimTrailingNewline(value)
		if len(value) == 0 {
			return fmt.Errorf("empty password on stdin")
		}
		secretID, err = setAssetSecret(cmd, cl, assetID, sshLoginName, value)
		if err != nil {
			return err
		}
	case "key":
		value, err := os.ReadFile(sshLoginKeyFile) // #nosec G304 -- key-file is the operator's chosen path
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		if len(value) == 0 {
			return fmt.Errorf("empty key file %q", sshLoginKeyFile)
		}
		secretID, err = setAssetSecret(cmd, cl, assetID, sshLoginName, value)
		if err != nil {
			return err
		}
	}

	// Read-modify-write: fetch the current SSH config, replace/append this login,
	// preserving host/target and the other logins.
	getReq := connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID})
	cl.Authorize(getReq)
	getResp, err := cl.Catalog().GetAsset(cmd.Context(), getReq)
	if err != nil {
		return err
	}

	cfg := getResp.Msg.GetAsset().GetSsh()
	if cfg == nil {
		cfg = &catalogv1.SSHConfig{}
	}

	entry := &catalogv1.SSHLogin{Login: sshLoginName, Kind: kind, SecretId: secretID}
	replaced := false
	for i, l := range cfg.GetLogins() {
		if l.GetLogin() == sshLoginName {
			cfg.Logins[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		cfg.Logins = append(cfg.Logins, entry)
	}

	updReq := connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetID,
		Config:  &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: cfg},
	})
	cl.Authorize(updReq)
	if _, err := cl.Catalog().UpdateAssetConfig(cmd.Context(), updReq); err != nil {
		return err
	}

	rows := make([][]string, 0, len(cfg.GetLogins()))
	msgs := make([]proto.Message, 0, len(cfg.GetLogins()))
	for _, l := range cfg.GetLogins() {
		rows = append(rows, sshLoginRow(l))
		msgs = append(msgs, l)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: sshLoginHeaders,
		Rows:    rows,
	})
}

func runAssetsSSHLoginList(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	assetID, err := cl.ResolveAsset(cmd.Context(), args[0])
	if err != nil {
		return err
	}

	req := connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID})
	cl.Authorize(req)
	resp, err := cl.Catalog().GetAsset(cmd.Context(), req)
	if err != nil {
		return err
	}

	logins := resp.Msg.GetAsset().GetSsh().GetLogins()
	rows := make([][]string, 0, len(logins))
	msgs := make([]proto.Message, 0, len(logins))
	for _, l := range logins {
		rows = append(rows, sshLoginRow(l))
		msgs = append(msgs, l)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: sshLoginHeaders,
		Rows:    rows,
	})
}

// setAssetSecret seals value under name for the asset and returns the sealed
// secret id.
func setAssetSecret(cmd *cobra.Command, cl *wardenclient.Client, assetID, name string, value []byte) (string, error) {
	req := connect.NewRequest(&vaultv1.SetAssetSecretRequest{
		AssetId: assetID,
		Name:    name,
		Value:   value,
	})
	cl.Authorize(req)
	resp, err := cl.Vault().SetAssetSecret(cmd.Context(), req)
	if err != nil {
		return "", err
	}
	return resp.Msg.GetId(), nil
}

// trimTrailingNewline strips a single trailing "\n" or "\r\n" so a secret typed
// or piped with a newline is stored without it.
func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

func runAssetsList(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	parent := ""
	if len(args) > 0 {
		parent = args[0]
	}

	assets, err := collectPages(func(token string) ([]*catalogv1.Asset, string, error) {
		req := connect.NewRequest(&catalogv1.ListAssetsRequest{
			Parent:    parent,
			Cascade:   assetsListCascade,
			PageSize:  100,
			PageToken: token,
		})
		cl.Authorize(req)
		resp, err := cl.Catalog().ListAssets(cmd.Context(), req)
		if err != nil {
			return nil, "", err
		}
		return resp.Msg.GetAssets(), resp.Msg.GetNextPageToken(), nil
	})
	if err != nil {
		return err
	}

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
			strings.Join(roleRefNames(access.GetActiveRoles(), access.GetActiveRoleIds()), ", "),
			strings.Join(roleRefNames(access.GetRequestableRoles(), access.GetRequestableRoleIds()), ", "),
		}},
	})
}

// roleRefNames renders role refs by name (its folder path suffixed when scoped, e.g.
// "shell.prod"), falling back to the raw id list when a server predates RoleRef.
func roleRefNames(refs []*catalogv1.RoleRef, ids []string) []string {
	if len(refs) == 0 {
		return ids
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		name := r.GetName()
		if fp := r.GetFolderPath(); fp != "" {
			name = name + "." + fp
		}
		out = append(out, name)
	}
	return out
}
