package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/trevex/jumpgate/cli/internal/config"
	"github.com/trevex/jumpgate/cli/internal/tunnel"
	"github.com/trevex/jumpgate/cli/internal/wardenclient"
)

var connectLogin string

var connectCmd = &cobra.Command{
	Use:   "connect [<login>@]<asset>",
	Short: "Open a session to an asset through the gateway",
	Args:  cobra.ExactArgs(1),
	RunE:  runConnectCmd,
}

func init() {
	connectCmd.Flags().StringVar(&connectLogin, "login", "", "login user on the asset (alternative to <login>@<asset>)")
	rootCmd.AddCommand(connectCmd)
}

func runConnectCmd(cmd *cobra.Command, args []string) error {
	cfg, err := effectiveConfig()
	if err != nil {
		return err
	}

	login, asset, err := parseTarget(args[0], connectLogin)
	if err != nil {
		return err
	}

	out, err := runConnect(cmd.Context(), cfg, login, asset)
	if err != nil {
		return err
	}
	// The SSH client over this tunnel is a later step; close it for now.
	_ = out.tunnel.Close()

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "tunnel established to %s as %s\n", asset, login)
	return nil
}

// connectResult carries the state a later SSH step needs: the ephemeral client
// signer whose public key admitted the session, and the raw gateway tunnel.
type connectResult struct {
	signer ssh.Signer
	tunnel net.Conn
}

// runConnect resolves the asset, generates an ephemeral client key, creates a
// session, and dials the gateway tunnel. It returns once the tunnel is open.
func runConnect(ctx context.Context, cfg config.Config, login, asset string) (*connectResult, error) {
	if cfg.WardenAddr == "" {
		return nil, errors.New("warden address is not set; pass --warden-addr, set JUMPGATE_WARDEN_ADDR, or configure it")
	}
	if cfg.Token == "" {
		return nil, errors.New("not authenticated; run `jumpgate login` first")
	}
	if login == "" {
		return nil, errors.New("no login specified; use <login>@<asset> or --login")
	}

	signer, kcPub, err := generateClientKey()
	if err != nil {
		return nil, err
	}

	wc := wardenclient.New(cfg.WardenAddr, cfg.Token)
	assetID, err := wc.ResolveAsset(ctx, asset)
	if err != nil {
		return nil, err
	}

	token, gatewayEndpoint, err := wc.CreateSession(ctx, assetID, kcPub)
	if err != nil {
		return nil, err
	}

	conn, err := tunnel.Dial(ctx, gatewayEndpoint, cfg.CAFile, assetID, token)
	if err != nil {
		return nil, err
	}

	return &connectResult{signer: signer, tunnel: conn}, nil
}

// generateClientKey creates an ephemeral ed25519 SSH keypair and returns the
// signer plus the authorized-keys-encoded public key sent to warden.
func generateClientKey() (ssh.Signer, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating client key: %w", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("building signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding public key: %w", err)
	}
	return signer, ssh.MarshalAuthorizedKey(sshPub), nil
}

// parseTarget splits a "<login>@<asset>" target. A bare asset is allowed when
// loginFlag supplies the login. The login may also be overridden by loginFlag.
func parseTarget(target, loginFlag string) (login, asset string, err error) {
	if i := strings.LastIndex(target, "@"); i >= 0 {
		login, asset = target[:i], target[i+1:]
	} else {
		asset = target
	}
	if loginFlag != "" {
		login = loginFlag
	}
	if asset == "" {
		return "", "", errors.New("no asset specified")
	}
	return login, asset, nil
}
