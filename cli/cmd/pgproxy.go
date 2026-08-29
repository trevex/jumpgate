package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/trevex/jumpgate/cli/internal/config"
	"github.com/trevex/jumpgate/cli/internal/tunnel"
	"github.com/trevex/jumpgate/cli/internal/wardenclient"
)

// sessionSetupTimeout bounds mint + dial for one connection, so a hung warden RPC
// or gateway dial cannot wedge shutdown (Ctrl-C): proxyOne must observe ctx even
// while setting up. Mirrors the pg-proxy worker's per-session setup bound.
const sessionSetupTimeout = 15 * time.Second

// pgProxyDeps are the injectable side effects of the postgres proxy: minting a
// per-connection session and dialing the gateway tunnel. Injected so the accept
// loop is testable without a real warden/gateway.
type pgProxyDeps struct {
	mint func(ctx context.Context) (token, endpoint string, err error)
	dial func(ctx context.Context, endpoint, token string) (net.Conn, error)
}

// runPostgresProxy binds a LOOPBACK-ONLY listener and proxies each accepted
// connection through a freshly-minted, recorded postgres session. With execArgs it
// runs that command against the port (PG* env set) and returns when it exits;
// otherwise it runs until ctx is cancelled.
func runPostgresProxy(ctx context.Context, deps pgProxyDeps, role, defaultDB string, port int, execArgs []string, out io.Writer) error {
	// SECURITY: 127.0.0.1 only. Each accepted connection mints a session as the
	// authenticated user with no auth on the local hop, so the port must never be
	// reachable off-host. Do not make the bind address configurable.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = ln.Close() }()
	bound := ln.Addr().(*net.TCPAddr).Port

	_, _ = fmt.Fprintf(out, "postgres proxy listening on 127.0.0.1:%d\n", bound)
	_, _ = fmt.Fprintf(out, "  psql \"host=127.0.0.1 port=%d user=%s dbname=%s sslmode=disable\"\n", bound, role, defaultDB)
	_, _ = fmt.Fprintln(out, "  (any libpq client works; each connection is its own recorded session)")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				proxyOne(ctx, deps, c)
			}()
		}
	}()

	var runErr error
	if len(execArgs) > 0 {
		runErr = runExec(ctx, execArgs, bound, role, defaultDB, out)
	} else {
		<-ctx.Done()
	}
	_ = ln.Close()
	cancel()
	wg.Wait()
	return runErr
}

// runPostgresConnect builds the proxy dependencies from the warden client and runs
// the loopback postgres proxy. A leading pre-flight mint both validates the DB-role
// entitlement (fail fast before binding) and yields the default database for the hint.
func runPostgresConnect(cmd *cobra.Command, cctx config.Context, wc *wardenclient.Client, assetID, role string, args []string) error {
	if role == "" {
		return errors.New("no role specified; use <role>@<asset> or --login")
	}
	ctx := cmd.Context()

	// Pre-flight: validate entitlement + learn the default database. The token is
	// discarded (never redeemed → no live session created).
	_, _, defaultDB, err := wc.CreatePostgresSession(ctx, assetID, role)
	if err != nil {
		return err
	}

	deps := pgProxyDeps{
		mint: func(c context.Context) (string, string, error) {
			tok, ep, _, err := wc.CreatePostgresSession(c, assetID, role)
			return tok, ep, err
		},
		dial: func(c context.Context, endpoint, token string) (net.Conn, error) {
			return tunnel.Dial(c, endpoint, cctx.CAFile, assetID, token)
		},
	}

	// Everything after `--` on the command line is the tool to launch, if any.
	var execArgs []string
	if d := cmd.ArgsLenAtDash(); d >= 0 {
		execArgs = args[d:]
	}

	return runPostgresProxy(ctx, deps, role, defaultDB, connectPort, execArgs, os.Stdout)
}

// proxyOne mints a session, dials the tunnel, and splices the local conn to it. A
// mint/dial failure closes only this connection (the accept loop keeps serving).
func proxyOne(ctx context.Context, deps pgProxyDeps, local net.Conn) {
	defer func() { _ = local.Close() }()

	// Bound setup so a slow/hung mint or dial cannot outlive a Ctrl-C: the derived
	// ctx is cancelled by both the timeout and the parent cancel.
	setupCtx, cancelSetup := context.WithTimeout(ctx, sessionSetupTimeout)
	token, endpoint, err := deps.mint(setupCtx)
	if err != nil {
		cancelSetup()
		slog.Warn("postgres session mint failed", "err", err)
		return
	}
	tun, err := deps.dial(setupCtx, endpoint, token)
	cancelSetup()
	if err != nil {
		slog.Warn("gateway dial failed", "err", err)
		return
	}
	defer func() { _ = tun.Close() }()

	// Whichever direction ends first tears down both — a client half-close (CloseWrite)
	// therefore truncates the other direction. Fine for postgres (libpq sends Terminate
	// then closes fully); do not rely on graceful half-close draining here.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(tun, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, tun); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// runExec runs execArgs with libpq PG* env pointing at the local proxy port. stdout
// is where the child's stdout goes (os.Stdout in the real command; a buffer in
// tests). Returns nil on a zero exit, else an error carrying the failure.
func runExec(ctx context.Context, execArgs []string, port int, role, defaultDB string, stdout io.Writer) error {
	cmd := exec.CommandContext(ctx, execArgs[0], execArgs[1:]...) //nolint:gosec // user-supplied command by design
	cmd.Env = append(os.Environ(),
		"PGHOST=127.0.0.1",
		fmt.Sprintf("PGPORT=%d", port),
		"PGUSER="+role,
		"PGDATABASE="+defaultDB,
		"PGSSLMODE=disable",
	)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s: %w", execArgs[0], err)
	}
	return nil
}
