package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/trevex/jumpgate/cli/internal/config"
	"github.com/trevex/jumpgate/cli/internal/sshclient"
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
	defer func() { _ = out.tunnel.Close() }()

	code, err := runSession(cmd.Context(), out.tunnel, login, out.signer)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

// runSession runs the interactive SSH client over the tunnel. When stdin is a
// terminal it switches the terminal to raw mode, requests a matching pty, and
// forwards window-size changes; otherwise it runs non-interactively.
func runSession(ctx context.Context, tunnel net.Conn, login string, signer ssh.Signer) (int, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return sshclient.Run(ctx, tunnel, login, signer, os.Stdin, os.Stdout, os.Stderr, nil)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return 0, fmt.Errorf("switching terminal to raw mode: %w", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	w, h, err := term.GetSize(fd)
	if err != nil {
		return 0, fmt.Errorf("reading terminal size: %w", err)
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	resize := make(chan [2]int, 1)
	stop := watchResize(fd, resize)
	defer stop()

	pty := &sshclient.PTY{Term: termType, W: w, H: h, Resize: resize}
	return sshclient.Run(ctx, tunnel, login, signer, os.Stdin, os.Stdout, os.Stderr, pty)
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
