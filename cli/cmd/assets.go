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
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
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

var assetsPGCmd = &cobra.Command{
	Use:   "pg",
	Short: "Manage PostgreSQL assets and their per-role auth",
}

var (
	pgCreateFolder   string
	pgCreateTarget   string
	pgCreateDatabase string
	pgCreateLogins   []string
)

var assetsPGCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a PostgreSQL asset with its connection config",
	Long: "Create a PostgreSQL asset and its connection config in one call. Each " +
		"--mtls-login adds an mtls login with no secret; use `assets pg login set` to " +
		"add password logins.",
	Args: cobra.ExactArgs(1),
	RunE: runAssetsPGCreate,
}

var assetsPGLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Manage the logins of a PostgreSQL asset",
}

var (
	pgLoginRole  string
	pgLoginKind  string
	pgLoginStdin bool
)

var assetsPGLoginSetCmd = &cobra.Command{
	Use:   "set <asset>",
	Short: "Add or replace a login on a PostgreSQL asset",
	Long: "Add or replace a login on a PostgreSQL asset. For --kind password the " +
		"secret is read from stdin (--password-stdin). The secret is sealed in the " +
		"vault and bound to the asset; mtls logins carry no secret.",
	Args: cobra.ExactArgs(1),
	RunE: runAssetsPGLoginSet,
}

var assetsListCascade bool

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

var assetsDeleteCmd = &cobra.Command{
	Use:   "delete <asset>",
	Short: "Delete an asset",
	Args:  cobra.ExactArgs(1),
	RunE:  runAssetsDelete,
}

var assetsRenameCmd = &cobra.Command{
	Use:   "rename <asset> <new-name>",
	Short: "Rename an asset",
	Args:  cobra.ExactArgs(2),
	RunE:  runAssetsRename,
}

var assetsMoveCmd = &cobra.Command{
	Use:   "move <asset> <folder>",
	Short: "Move an asset into another folder",
	Args:  cobra.ExactArgs(2),
	RunE:  runAssetsMove,
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

	assetsPGCreateCmd.Flags().StringVar(&pgCreateFolder, "folder", "", "folder id or name (required)")
	assetsPGCreateCmd.Flags().StringVar(&pgCreateTarget, "target", "", "target host:port")
	assetsPGCreateCmd.Flags().StringVar(&pgCreateDatabase, "database", "", "default database")
	assetsPGCreateCmd.Flags().StringSliceVar(&pgCreateLogins, "mtls-login", nil, "mtls login role to allow (repeatable or comma-separated)")
	_ = assetsPGCreateCmd.MarkFlagRequired("folder")

	assetsPGLoginSetCmd.Flags().StringVar(&pgLoginRole, "role", "", "login role (required)")
	assetsPGLoginSetCmd.Flags().StringVar(&pgLoginKind, "kind", "", "auth kind: password|mtls (required)")
	assetsPGLoginSetCmd.Flags().BoolVar(&pgLoginStdin, "password-stdin", false, "read the password from stdin (kind=password)")
	_ = assetsPGLoginSetCmd.MarkFlagRequired("role")
	_ = assetsPGLoginSetCmd.MarkFlagRequired("kind")

	assetsPGLoginCmd.AddCommand(assetsPGLoginSetCmd)

	assetsPGCmd.AddCommand(assetsPGCreateCmd)
	assetsPGCmd.AddCommand(assetsPGLoginCmd)

	assetsListCmd.Flags().BoolVar(&assetsListCascade, "cascade", false, "include assets in all descendant folders")

	assetsCmd.AddCommand(assetsSSHCmd)
	assetsCmd.AddCommand(assetsPGCmd)
	assetsCmd.AddCommand(assetsListCmd)
	assetsCmd.AddCommand(assetsGetCmd)
	assetsCmd.AddCommand(assetsDeleteCmd)
	assetsCmd.AddCommand(assetsRenameCmd)
	assetsCmd.AddCommand(assetsMoveCmd)
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
	logins := make([]*catalogv1.SSHLoginInput, 0, len(sshCreateLogins))
	for _, name := range sshCreateLogins {
		logins = append(logins, &catalogv1.SSHLoginInput{
			Login: name,
			Auth:  &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}},
		})
	}

	// One call: the asset and its SSH config are created together, so there is no
	// window where a bare asset exists without config.
	createReq := connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     args[0],
		Config: &catalogv1.CreateAssetRequest_Ssh{Ssh: &catalogv1.SSHConfigInput{
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

	// For password/key, read the new secret; it is sealed server-side in-tx as
	// part of UpdateAssetConfig (no separate vault round-trip). ca has no secret.
	var newSecret []byte
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
		newSecret = value
	case "key":
		value, err := os.ReadFile(sshLoginKeyFile) // #nosec G304 -- key-file is the operator's chosen path
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		if len(value) == 0 {
			return fmt.Errorf("empty key file %q", sshLoginKeyFile)
		}
		newSecret = value
	}

	// Read-modify-write: fetch the current SSH config, replace/append this login,
	// preserving host/target and the other logins (with their existing secrets).
	getReq := connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID})
	cl.Authorize(getReq)
	getResp, err := cl.Catalog().GetAsset(cmd.Context(), getReq)
	if err != nil {
		return err
	}

	cur := getResp.Msg.GetAsset().GetSsh()

	// Rebuild the write-side input from the current read-side config, mapping each
	// existing login to its input arm and preserving its already-sealed secret.
	input := &catalogv1.SSHConfigInput{}
	if cur != nil {
		input.HostPublicKey = cur.GetHostPublicKey()
		input.TargetAddress = cur.GetTargetAddress()
		for _, l := range cur.GetLogins() {
			if l.GetLogin() == sshLoginName {
				continue // the target login is (re)built below
			}
			input.Logins = append(input.Logins, existingLoginInput(l))
		}
	}

	input.Logins = append(input.Logins, newLoginInput(sshLoginName, kind, newSecret))

	updReq := connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetID,
		Config:  &catalogv1.UpdateAssetConfigRequest_Ssh{Ssh: input},
	})
	cl.Authorize(updReq)
	if _, err := cl.Catalog().UpdateAssetConfig(cmd.Context(), updReq); err != nil {
		return err
	}

	rows := make([][]string, 0, len(input.GetLogins()))
	msgs := make([]proto.Message, 0, len(input.GetLogins()))
	for _, l := range input.GetLogins() {
		rows = append(rows, sshLoginInputRow(l))
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

// existingLoginInput maps a read-side login to its write-side input arm,
// preserving the already-sealed secret (by id) for password/key logins.
func existingLoginInput(l *catalogv1.SSHLogin) *catalogv1.SSHLoginInput {
	in := &catalogv1.SSHLoginInput{Login: l.GetLogin()}
	switch l.GetKind() {
	case "password":
		in.Auth = &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: l.GetSecretId()},
		}}
	case "key":
		in.Auth = &catalogv1.SSHLoginInput_Key{Key: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: l.GetSecretId()},
		}}
	default: // ca (or unknown → ca, which carries no secret)
		in.Auth = &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}
	}
	return in
}

// newLoginInput builds the write-side input for the login being added/replaced.
// For password/key, secret is the new plaintext to seal server-side in-tx.
func newLoginInput(login, kind string, secret []byte) *catalogv1.SSHLoginInput {
	in := &catalogv1.SSHLoginInput{Login: login}
	switch kind {
	case "password":
		in.Auth = &catalogv1.SSHLoginInput_Password{Password: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_NewValue{NewValue: secret},
		}}
	case "key":
		in.Auth = &catalogv1.SSHLoginInput_Key{Key: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_NewValue{NewValue: secret},
		}}
	default: // ca
		in.Auth = &catalogv1.SSHLoginInput_Ca{Ca: &catalogv1.CaAuth{}}
	}
	return in
}

// sshLoginInputKind renders the auth kind of a write-side login input.
func sshLoginInputKind(l *catalogv1.SSHLoginInput) string {
	switch l.GetAuth().(type) {
	case *catalogv1.SSHLoginInput_Password:
		return "password"
	case *catalogv1.SSHLoginInput_Key:
		return "key"
	default:
		return "ca"
	}
}

func sshLoginInputRow(l *catalogv1.SSHLoginInput) []string {
	return []string{l.GetLogin(), sshLoginInputKind(l)}
}

// trimTrailingNewline strips a single trailing "\n" or "\r\n" so a secret typed
// or piped with a newline is stored without it.
func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

var pgLoginHeaders = []string{"ROLE", "KIND"}

func runAssetsPGCreate(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, pgCreateFolder)
	if err != nil {
		return err
	}

	// Inline --mtls-login entries carry no secret; password logins are added
	// afterwards via `assets pg login set`.
	logins := make([]*catalogv1.PostgresLoginInput, 0, len(pgCreateLogins))
	for _, role := range pgCreateLogins {
		logins = append(logins, newPgLoginInput(role, "mtls", nil))
	}

	createReq := connect.NewRequest(&catalogv1.CreateAssetRequest{
		FolderId: folderID,
		Name:     args[0],
		Config: &catalogv1.CreateAssetRequest_Postgres{Postgres: &catalogv1.PostgresConfigInput{
			TargetAddress:   pgCreateTarget,
			DefaultDatabase: pgCreateDatabase,
			Logins:          logins,
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

func runAssetsPGLoginSet(cmd *cobra.Command, args []string) error {
	kind := pgLoginKind
	switch kind {
	case "password", "mtls":
	default:
		return fmt.Errorf("invalid --kind %q (want password|mtls)", kind)
	}

	// Validate the secret source up front so we fail before any RPC.
	switch kind {
	case "password":
		if !pgLoginStdin {
			return fmt.Errorf("--kind password requires --password-stdin")
		}
	case "mtls":
		if pgLoginStdin {
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

	// For password, read the new secret; it is sealed server-side in-tx as part of
	// UpdateAssetConfig (no separate vault round-trip). mtls has no secret.
	var newSecret []byte
	if kind == "password" {
		value, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		value = trimTrailingNewline(value)
		if len(value) == 0 {
			return fmt.Errorf("empty password on stdin")
		}
		newSecret = value
	}

	// Read-modify-write: fetch the current Postgres config, replace/append this
	// login, preserving target/database and the other logins (with their existing
	// secrets).
	getReq := connect.NewRequest(&catalogv1.GetAssetRequest{AssetId: assetID})
	cl.Authorize(getReq)
	getResp, err := cl.Catalog().GetAsset(cmd.Context(), getReq)
	if err != nil {
		return err
	}

	cur := getResp.Msg.GetAsset().GetPostgres()

	input := &catalogv1.PostgresConfigInput{}
	if cur != nil {
		input.TargetAddress = cur.GetTargetAddress()
		input.DefaultDatabase = cur.GetDefaultDatabase()
		input.TargetServerCa = cur.GetTargetServerCa()
		for _, l := range cur.GetLogins() {
			if l.GetRole() == pgLoginRole {
				continue // the target login is (re)built below
			}
			input.Logins = append(input.Logins, existingPgLoginInput(l))
		}
	}

	input.Logins = append(input.Logins, newPgLoginInput(pgLoginRole, kind, newSecret))

	updReq := connect.NewRequest(&catalogv1.UpdateAssetConfigRequest{
		AssetId: assetID,
		Config:  &catalogv1.UpdateAssetConfigRequest_Postgres{Postgres: input},
	})
	cl.Authorize(updReq)
	if _, err := cl.Catalog().UpdateAssetConfig(cmd.Context(), updReq); err != nil {
		return err
	}

	rows := make([][]string, 0, len(input.GetLogins()))
	msgs := make([]proto.Message, 0, len(input.GetLogins()))
	for _, l := range input.GetLogins() {
		rows = append(rows, pgLoginInputRow(l))
		msgs = append(msgs, l)
	}
	return output.RenderProtoList(cmd.OutOrStdout(), flagOutput, msgs, &output.Table{
		Headers: pgLoginHeaders,
		Rows:    rows,
	})
}

// existingPgLoginInput maps a read-side login to its write-side input arm,
// preserving the already-sealed secret (by id) for password logins.
func existingPgLoginInput(l *catalogv1.PostgresLogin) *catalogv1.PostgresLoginInput {
	in := &catalogv1.PostgresLoginInput{Role: l.GetRole()}
	if l.GetKind() == "password" {
		in.Auth = &catalogv1.PostgresLoginInput_Password{Password: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_ExistingSecretId{ExistingSecretId: l.GetSecretId()},
		}}
	} else { // mtls (or unknown → mtls, which carries no secret)
		in.Auth = &catalogv1.PostgresLoginInput_Mtls{Mtls: &catalogv1.MtlsAuth{}}
	}
	return in
}

// newPgLoginInput builds the write-side input for the login being added/replaced.
// For password, secret is the new plaintext to seal server-side in-tx.
func newPgLoginInput(role, kind string, secret []byte) *catalogv1.PostgresLoginInput {
	in := &catalogv1.PostgresLoginInput{Role: role}
	switch kind {
	case "password":
		in.Auth = &catalogv1.PostgresLoginInput_Password{Password: &catalogv1.SecretAuth{
			Source: &catalogv1.SecretAuth_NewValue{NewValue: secret},
		}}
	default: // mtls
		in.Auth = &catalogv1.PostgresLoginInput_Mtls{Mtls: &catalogv1.MtlsAuth{}}
	}
	return in
}

// pgLoginInputKind renders the auth kind of a write-side login input.
func pgLoginInputKind(l *catalogv1.PostgresLoginInput) string {
	if _, ok := l.GetAuth().(*catalogv1.PostgresLoginInput_Password); ok {
		return "password"
	}
	return "mtls"
}

func pgLoginInputRow(l *catalogv1.PostgresLoginInput) []string {
	return []string{l.GetRole(), pgLoginInputKind(l)}
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

func runAssetsDelete(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	assetID, err := cl.ResolveAsset(cmd.Context(), args[0])
	if err != nil {
		return err
	}

	req := connect.NewRequest(&catalogv1.DeleteAssetRequest{AssetId: assetID})
	cl.Authorize(req)
	if _, err := cl.Catalog().DeleteAsset(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "deleted asset %s\n", args[0])
	return nil
}

func runAssetsRename(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	assetID, err := cl.ResolveAsset(cmd.Context(), args[0])
	if err != nil {
		return err
	}

	name := args[1]
	req := connect.NewRequest(&catalogv1.UpdateAssetRequest{AssetId: assetID, Name: &name})
	cl.Authorize(req)
	if _, err := cl.Catalog().UpdateAsset(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "renamed asset %s to %s\n", args[0], name)
	return nil
}

func runAssetsMove(cmd *cobra.Command, args []string) error {
	cl, err := newClient()
	if err != nil {
		return err
	}

	assetID, err := cl.ResolveAsset(cmd.Context(), args[0])
	if err != nil {
		return err
	}

	folderID, err := resolveFolderID(cmd.Context(), cl, args[1])
	if err != nil {
		return err
	}

	req := connect.NewRequest(&catalogv1.UpdateAssetRequest{AssetId: assetID, FolderId: &folderID})
	cl.Authorize(req)
	if _, err := cl.Catalog().UpdateAsset(cmd.Context(), req); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "moved asset %s into %s\n", args[0], args[1])
	return nil
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
