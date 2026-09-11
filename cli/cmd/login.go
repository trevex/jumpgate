package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	loginSSO      bool
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
	loginCmd.Flags().BoolVar(&loginSSO, "sso", false, "sign in via the browser using single sign-on (OIDC)")
	loginCmd.Flags().StringVar(&loginContext, "context", "default", "config context to store the credentials under")
}

func runLogin(cmd *cobra.Command, _ []string) error {
	if loginSSO {
		if loginEmail != "" || loginPassword != "" {
			return errors.New("--sso cannot be combined with --email or --password")
		}
		return runLoginSSO(cmd)
	}
	if loginEmail == "" {
		return errors.New("--email is required (or use --sso)")
	}

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

// httpClientWithCA is like httpClient but, for an https:// address with a
// configured caFile, trusts that CA bundle instead of the system roots so a
// self-signed warden (--ca) is reachable.
func httpClientWithCA(addr, caFile string) (*http.Client, error) {
	if !strings.HasPrefix(addr, "https://") || caFile == "" {
		hc, _ := httpClient(addr).(*http.Client)
		if hc == nil {
			hc = http.DefaultClient
		}
		return hc, nil
	}
	pemBytes, err := os.ReadFile(caFile) // #nosec G304 -- caFile comes from CLI config, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("reading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}, nil
}

// ssoResult carries the outcome of the loopback OIDC callback: either a
// one-time code to exchange, or an error reason reported by warden.
type ssoResult struct {
	code string
	err  string
}

// ssoCallbackHandler serves the loopback /callback redirect target: it reads
// ?code=/?error=, renders a minimal HTML page for the browser tab, and
// publishes the result on resultCh (buffered; only the first call matters).
func ssoCallbackHandler(resultCh chan<- ssoResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := ssoResult{code: r.URL.Query().Get("code"), err: r.URL.Query().Get("error")}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != "" {
			_, _ = fmt.Fprintf(w, "<html><body><h1>Sign-in failed</h1><p>%s</p></body></html>", html.EscapeString(res.err))
		} else {
			_, _ = fmt.Fprint(w, "<html><body><h1>Sign-in complete</h1><p>You can close this tab.</p></body></html>")
		}
		select {
		case resultCh <- res:
		default:
		}
	}
}

// exchangeCLICode posts the one-time code to warden's CLI code-exchange
// endpoint and returns the bearer token.
func exchangeCLICode(client *http.Client, wardenAddr, code string) (string, error) {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(wardenAddr, "/")+"/auth/oidc/cli/exchange", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("exchange failed with status %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decoding exchange response: %w", err)
	}
	return out.Token, nil
}

// runLoginSSO signs in via warden's browser-based OIDC dance: it opens a
// loopback HTTP server, sends the user's browser to warden's cli/login
// endpoint, waits for the redirect back with a one-time code, and exchanges
// that code for a bearer token.
func runLoginSSO(cmd *cobra.Command) error {
	ctx, err := resolveContext()
	if err != nil {
		return err
	}
	if ctx.WardenAddr == "" {
		return errors.New("warden address is not set; pass --warden-addr, set JUMPGATE_WARDEN_ADDR, or configure it")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("starting loopback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	resultCh := make(chan ssoResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", ssoCallbackHandler(resultCh))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	loginURL := strings.TrimRight(ctx.WardenAddr, "/") + "/auth/oidc/cli/login?redirect_uri=" + url.QueryEscape(redirectURI)
	_, _ = fmt.Fprintln(cmd.OutOrStderr(), "Opening browser to sign in...")
	if err := openBrowser(loginURL); err != nil {
		_, _ = fmt.Fprintf(cmd.OutOrStderr(), "Open this URL to sign in:\n%s\n", loginURL)
	}

	var res ssoResult
	select {
	case res = <-resultCh:
	case <-time.After(2 * time.Minute):
		return errors.New("timed out waiting for sign-in")
	case <-cmd.Context().Done():
		return cmd.Context().Err()
	}

	if res.err != "" {
		return fmt.Errorf("single sign-on failed: %s", res.err)
	}
	if res.code == "" {
		return errors.New("single sign-on failed: no code returned")
	}

	httpc, err := httpClientWithCA(ctx.WardenAddr, ctx.CAFile)
	if err != nil {
		return err
	}
	token, err := exchangeCLICode(httpc, ctx.WardenAddr, res.code)
	if err != nil {
		return fmt.Errorf("exchanging sign-in code: %w", err)
	}
	if token == "" {
		return errors.New("single sign-on failed: empty token")
	}

	if err := config.UpsertContext(loginContext, config.Context{
		WardenAddr: ctx.WardenAddr,
		CAFile:     ctx.CAFile,
		Token:      token,
	}, true); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "logged in via SSO; context %q is now current\n", loginContext)
	return nil
}
