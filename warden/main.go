// Command warden is the jumpgate control plane: identity, authorization,
// JIT/approvals, vault, audit, and the API. M2a wires config, DB migrations, a
// connection pool, and graceful shutdown; it serves /healthz.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/bootstrap"
	"github.com/trevex/jumpgate/warden/internal/config"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
	"github.com/trevex/jumpgate/warden/internal/pg"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if err := migrate.Up(cfg.DatabaseURL); err != nil {
		return err
	}

	pool, err := pg.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	q := gen.New(pool)
	if err := bootstrap.EnsureAdmin(ctx, q, cfg.BootstrapAdminEmail, cfg.BootstrapAdminPassword); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := q.DeleteExpiredAuthTokens(ctx); err != nil {
					slog.Warn("token gc failed", "err", err)
				}
			}
		}
	}()

	// Build the access-request Service ONCE and share it: the RPC handlers and the
	// expiry reaper must use the same terminator + audit instance.
	// NoopTerminator until M4 wires live-session teardown against the gateway.
	arSvc := accessrequest.NewService(
		pool,
		audit.New(pool),
		approvals.New(pool),
		authz.NewRoleResolver(pool),
		accessrequest.NoopTerminator{},
		cfg.MaxGrantTTL,
	)
	// Expiry reaper: sweeps expired grants, audits access_grant.expired, and tears
	// down live sessions. Exits on ctx.Done() (graceful shutdown).
	go arSvc.RunReaper(ctx, cfg.ReaperInterval)

	// Build the vault sealer ONCE. An unset master key disables the vault (nil
	// sealer): VaultService still mounts but its sealing write paths fail closed.
	// A present-but-invalid key is a config error and is fatal.
	var sealer *secrets.Sealer
	key, err := secrets.MasterKeyFromConfig(cfg.VaultMasterKey)
	switch {
	case errors.Is(err, secrets.ErrNotConfigured):
		slog.Warn("vault disabled: VAULT_MASTER_KEY unset")
	case err != nil:
		return err
	default:
		sealer, err = secrets.NewSealer(key)
		if err != nil {
			return err
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", httpapi.NewRouter(pool))
	if err := rpc.Register(mux, pool, arSvc, sealer); err != nil {
		return err
	}

	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		Protocols:         &protos,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("warden listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return nil
}
