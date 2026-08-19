// Command warden is the jumpgate control plane: identity, authorization,
// JIT/approvals, vault, audit, and the API. M2a wires config, DB migrations, a
// connection pool, and graceful shutdown; it serves /healthz.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/bootstrap"
	"github.com/trevex/jumpgate/warden/internal/config"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/db/migrate"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/pg"
	"github.com/trevex/jumpgate/warden/internal/recording"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/vault"
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

	// Build the audit Logger ONCE and share it: the outbox drainer (below) and every
	// enqueuer/appender must operate over the same pool so the advisory lock and the
	// hash chain stay consistent.
	auditLog := audit.New(pool)
	// Transactional audit outbox drainer: moves events enqueued durably inside domain
	// transactions (audit_outbox) into the hash-chained audit_log, closing the
	// post-commit crash window. Exits on ctx.Done() (graceful shutdown).
	go auditLog.RunDrainer(ctx, cfg.AuditDrainInterval)

	// Build the access-request Service ONCE and share it: the RPC handlers and the
	// expiry reaper must use the same terminator + audit instance. The terminator is
	// the real grant-keyed dataplane.Terminator (stateless): grant revocation/expiry/
	// deactivation now re-evaluates closures and tears down live sessions via
	// LISTEN/NOTIFY. (A second instance in rpc.Register for DataplaneServer is fine.)
	authorizer := authz.NewSQLAuthorizer(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	arSvc := accessrequest.NewService(
		pool,
		auditLog,
		approvals.New(pool),
		authz.NewRoleResolver(pool),
		terminator,
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

	// Build the CLI-facing session admission service. It requires the vault (to
	// unseal the signing key) and an initialized active session signing key; absent
	// either, CreateSession is disabled (nil service → SessionService not mounted).
	//
	// setupSvc backs the data-plane worker RPCs (SetupSession + WorkerStream); it is
	// built alongside sessionSvc under the same preconditions and shares the active
	// signing key (as a verifier). The worker registry is always created (it is
	// rebuilt from reconnecting streams), but DataplaneService only mounts when
	// setupSvc is non-nil.
	registry := dataplane.NewRegistry()
	// Start the teardown Listener on the lifecycle ctx, sharing the DataplaneService's
	// Registry so grant-keyed teardown NOTIFYs reach locally-owned worker streams. It
	// is cheap (one LISTEN conn) and a harmless no-op when no DataplaneService is
	// mounted (no sinks registered).
	go func() {
		if err := dataplane.NewListener(pool, registry).Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("teardown listener stopped", "err", err)
		}
	}()
	// Continuously reconcile live sessions with current authorization: the sweeper
	// re-evaluates owned sessions on authorization-change notifications (and on a
	// periodic backstop), tearing down those that lost their standing access, and
	// garbage-collects sessions of unreachable workers and stuck teardowns.
	sweeper := dataplane.NewSweeper(pool, registry, terminator)
	go sweeper.RunAuthzSweeper(ctx, cfg.AuthzSweepInterval, cfg.AuthzSweepDebounce)
	go sweeper.RunGC(ctx, cfg.OrphanGCInterval, cfg.OrphanGrace, cfg.TeardownGrace)
	var sessionSvc *session.Service
	var setupSvc *dataplane.SetupService
	var sessionPubKey ed25519.PublicKey
	if sealer != nil {
		ks := session.NewKeyStore(gen.New(pool), sealer)
		priv, pub, err := ks.LoadActive(ctx)
		if errors.Is(err, session.ErrNoActiveKey) {
			slog.Warn("no active session signing key; CreateSession disabled until initialized")
		} else if err != nil {
			return err
		} else {
			sessionPubKey = pub
			sessionSvc = session.NewService(gen.New(pool), authorizer, sessiontoken.NewMinter(priv), cfg.GatewayEndpoint, cfg.SessionTokenTTL)
			broker := vault.NewBroker(pool, sealer, authorizer, auditLog)
			verifier := sessiontoken.NewVerifier(pub)
			setupSvc = dataplane.NewSetupService(pool, verifier, authorizer, broker, auditLog, cfg.SSHCertMaxTTL)
		}
	}

	// User-facing (bearer) mux + server: Auth/Identity/Catalog/Access/AccessRequest/
	// Session/Vault. The worker/gateway services live ONLY on the mesh listener below.
	mux := http.NewServeMux()
	mux.Handle("/", httpapi.NewRouter(pool))
	// Recording download presigning: with a bucket configured, RecordingService
	// issues short-lived presigned GET URLs against the object store; without one,
	// a nil presigner makes the download path fail closed.
	var recordingPresign rpc.Presigner
	if cfg.RecordingBucket != "" {
		presign, err := recording.NewS3Presigner(ctx, cfg.RecordingBucket, cfg.RecordingS3Endpoint, cfg.RecordingS3Region)
		if err != nil {
			return err
		}
		recordingPresign = presign
	} else {
		slog.Warn("recording retrieval disabled (no RECORDING_BUCKET); download fails closed")
	}
	if err := rpc.RegisterUserServices(mux, pool, arSvc, sealer, sessionSvc, recordingPresign, cfg.RecordingURLTTL); err != nil {
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

	// Second, mTLS "mesh" listener: serves Dataplane + Gateway to workers/gateway.
	// Peer identity is the mTLS client cert URI SAN (mesh.Middleware). Degraded boot:
	// if MESH_LISTEN_ADDR is unset or the cert files are missing/unreadable, warden
	// logs a warning and serves only the user API (workers/gateway cannot connect).
	meshSrv := buildMeshServer(cfg, pool, auditLog, setupSvc, registry, sessionPubKey)

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("warden listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	if meshSrv != nil {
		go func() {
			slog.Info("warden mesh listening", "addr", meshSrv.Addr)
			if err := meshSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErr <- err
			}
		}()
	}

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if meshSrv != nil {
		if err := meshSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("mesh server shutdown", "err", err)
		}
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return nil
}

// buildMeshServer constructs warden's mTLS mesh HTTP server (Dataplane + Gateway
// behind mesh.Middleware), or returns nil for a degraded boot when the mesh
// listener is disabled (MESH_LISTEN_ADDR unset) or its cert files cannot be loaded.
func buildMeshServer(cfg config.Config, pool *pgxpool.Pool, auditLog *audit.Logger, setupSvc *dataplane.SetupService, registry *dataplane.Registry, sessionPubKey ed25519.PublicKey) *http.Server {
	if cfg.MeshListenAddr == "" {
		slog.Warn("mesh listener disabled: MESH_LISTEN_ADDR unset (workers/gateway cannot connect)")
		return nil
	}
	certPEM, keyPEM, caPEM, err := readMeshCerts(cfg)
	if err != nil {
		slog.Warn("mesh listener disabled: cert files unreadable", "err", err)
		return nil
	}
	tlsCfg, err := mesh.ServerTLSConfig(certPEM, keyPEM, caPEM)
	if err != nil {
		slog.Warn("mesh listener disabled: invalid TLS material", "err", err)
		return nil
	}
	// Advertise h2 via ALPN so the bidi/server-streaming mesh RPCs negotiate HTTP/2.
	tlsCfg.NextProtos = []string{"h2", "http/1.1"}

	meshMux := http.NewServeMux()
	if err := rpc.RegisterMeshServices(meshMux, pool, auditLog, setupSvc, registry, rpc.NewGatewayServer(registry, sessionPubKey)); err != nil {
		slog.Warn("mesh listener disabled: service registration failed", "err", err)
		return nil
	}
	// Enable HTTP/2 over TLS: the mesh RPCs (WorkerStream / WatchWorkers /
	// SetupSession) are gRPC and require h2. Advertising h2 in NextProtos alone is
	// not enough — the server must also install the h2 handler, which the
	// Protocols field does. HTTP/1.1 stays enabled as a fallback.
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	return &http.Server{
		Addr:              cfg.MeshListenAddr,
		Handler:           mesh.Middleware(meshMux),
		TLSConfig:         tlsCfg,
		Protocols:         &protos,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// readMeshCerts loads warden's mesh leaf cert/key and the mesh CA bundle from the
// configured PEM files. All three must be present and readable.
func readMeshCerts(cfg config.Config) (certPEM, keyPEM, caPEM []byte, err error) {
	if cfg.MeshCertFile == "" || cfg.MeshKeyFile == "" || cfg.MeshCAFile == "" {
		return nil, nil, nil, errors.New("MESH_CERT_FILE/MESH_KEY_FILE/MESH_CA_FILE must all be set")
	}
	if certPEM, err = os.ReadFile(cfg.MeshCertFile); err != nil {
		return nil, nil, nil, err
	}
	if keyPEM, err = os.ReadFile(cfg.MeshKeyFile); err != nil {
		return nil, nil, nil, err
	}
	if caPEM, err = os.ReadFile(cfg.MeshCAFile); err != nil {
		return nil, nil, nil, err
	}
	return certPEM, keyPEM, caPEM, nil
}
