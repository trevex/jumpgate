package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/trevex/jumpgate/cli/internal/config"
	authv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
)

var (
	loginEmail    string
	loginPassword string
	loginContext  = "default"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to warden and store a bearer token",
	RunE:  runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginEmail, "email", "", "account email")
	loginCmd.Flags().StringVar(&loginPassword, "password", "", "account password (prompted if omitted on a TTY)")
	loginCmd.Flags().StringVar(&loginContext, "context", "default", "config context to store the credentials under")
	_ = loginCmd.MarkFlagRequired("email")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	ctx, err := resolveContext()
	if err != nil {
		return err
	}
	if ctx.WardenAddr == "" {
		return errors.New("warden address is not set; pass --warden-addr, set JUMPGATE_WARDEN_ADDR, or configure it")
	}

	password, err := resolvePassword()
	if err != nil {
		return err
	}

	client := authv1connect.NewAuthServiceClient(httpClient(ctx.WardenAddr), ctx.WardenAddr)
	resp, err := client.Login(cmd.Context(), connect.NewRequest(&authv1.LoginRequest{
		Email:    loginEmail,
		Password: password,
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnauthenticated {
			return errors.New("login failed: invalid email or password")
		}
		return fmt.Errorf("login failed: %w", err)
	}

	if err := config.UpsertContext(loginContext, config.Context{
		WardenAddr: ctx.WardenAddr,
		CAFile:     ctx.CAFile,
		Token:      resp.Msg.GetToken(),
	}, true); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "logged in as %s; context %q is now current\n", loginEmail, loginContext)
	return nil
}

// resolvePassword returns the password from the flag, or prompts for it when
// omitted and stdin is a terminal. It errors if neither is available.
func resolvePassword() (string, error) {
	if loginPassword != "" {
		return loginPassword, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no password provided: pass --password or run on a terminal to be prompted")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

// httpClient returns an HTTP client suited to the given warden address. For a
// plaintext http:// address it enables unencrypted HTTP/2 (h2c) alongside
// HTTP/1.1 so it works whether or not warden negotiates h2c; https:// uses the
// default client.
func httpClient(addr string) connect.HTTPClient {
	if !strings.HasPrefix(addr, "http://") {
		return http.DefaultClient
	}
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: &protos}}
}
