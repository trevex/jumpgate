// Package app owns Warden's dependency graph and process lifecycle.
package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/bootstrap"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/config"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/httpapi"
	"github.com/trevex/jumpgate/warden/internal/identity"
	"github.com/trevex/jumpgate/warden/internal/mesh"
	"github.com/trevex/jumpgate/warden/internal/postgres"
	"github.com/trevex/jumpgate/warden/internal/postgres/migrate"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/recording"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/sessiontoken"
	"github.com/trevex/jumpgate/warden/internal/vault"
	"github.com/trevex/jumpgate/warden/internal/webcors"
	"github.com/trevex/jumpgate/warden/internal/webui"
)

// Run constructs and runs the Warden application until ctx is cancelled or a
// server fails. The caller owns process concerns such as signals and logging.
func Run(ctx context.Context, cfg config.Config) error {
	if err := migrate.Up(cfg.DatabaseURL); err != nil {
		return err
	}

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	q := sqlc.New(pool)
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
	// LISTEN/NOTIFY. The same instance is injected into the user and mesh adapters.
	authorizer := authz.NewSQLAuthorizer(pool)
	roleResolver := authz.NewRoleResolver(pool)
	approvalResolver := approvals.New(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	arSvc := accessrequest.NewService(
		pool,
		auditLog,
		approvalResolver,
		roleResolver,
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
		ks := session.NewKeyStore(sqlc.New(pool), sealer)
		priv, pub, err := ks.LoadActive(ctx)
		if errors.Is(err, session.ErrNoActiveKey) {
			slog.Warn("no active session signing key; CreateSession disabled until initialized")
		} else if err != nil {
			return err
		} else {
			sessionPubKey = pub
			sessionSvc = session.NewService(sqlc.New(pool), authorizer, sessiontoken.NewMinter(priv), cfg.GatewayEndpoint, cfg.SessionTokenTTL)
			broker := vault.NewBroker(pool, sealer, authorizer, auditLog)
			verifier := sessiontoken.NewVerifier(pub)
			setupSvc = dataplane.NewSetupService(pool, verifier, authorizer, broker, auditLog, cfg.SSHCertMaxTTL)
		}
	}

	// Recording download presigning: with a bucket configured, RecordingService
	// issues short-lived presigned GET URLs against the object store; without one,
	// a nil presigner makes the download path fail closed. The concrete
	// *recording.S3Presigner also implements httpapi.ObjectGetter for the
	// server-side cast proxy — stored separately so both are threaded to their
	// respective consumers without a type assertion.
	var recordingPresign rpc.Presigner
	var castGetter httpapi.ObjectGetter
	if cfg.RecordingBucket != "" {
		presign, err := recording.NewS3Presigner(ctx, cfg.RecordingBucket, cfg.RecordingS3Endpoint, cfg.RecordingS3Region)
		if err != nil {
			return err
		}
		recordingPresign = presign
		castGetter = presign // *S3Presigner implements ObjectGetter (GetObject)
		// Anchor the audit hash-chain tip to the same object store so tail truncation
		// of the in-DB chain is detectable. *S3Presigner.Put satisfies audit.AnchorStore.
		// Best-effort: errors are logged inside RunAnchorer and never block. Exits on
		// ctx.Done() (graceful shutdown).
		go auditLog.RunAnchorer(ctx, presign, cfg.AuditAnchorInterval)
	} else {
		slog.Warn("recording retrieval disabled (no RECORDING_BUCKET); download fails closed")
	}

	// User-facing (bearer) mux + server: Auth/Identity/Catalog/Access/AccessRequest/
	// Session/Vault. The worker/gateway services live ONLY on the mesh listener below.
	//
	// Build the token lookup once here and share it with both the RPC interceptor
	// and the HTTP cookie-auth middleware.
	apiQ := sqlc.New(pool)
	apiTokens := auth.NewTokenService(apiQ)
	apiLookup := auth.Lookup{Tokens: apiTokens, Q: apiQ}
	userServices := rpc.UserServices{
		Lookup:        apiLookup,
		Auth:          rpc.NewAuthServer(apiQ, apiTokens, authorizer, cfg.CookieSecure()),
		Identity:      identity.NewHandler(identity.NewService(pool, arSvc, terminator, authorizer), apiguard.New(authorizer, apiQ)),
		Catalog:       catalog.NewHandler(catalog.NewService(pool, sealer, terminator, authorizer, arSvc), apiguard.New(authorizer, apiQ)),
		Access:        rpc.NewAccessServer(apiQ, pool, roleResolver, authorizer, arSvc, arSvc),
		AccessRequest: rpc.NewAccessRequestServer(approvalResolver, arSvc, authorizer, apiQ),
		Vault:         rpc.NewVaultServer(apiQ, sealer, authorizer),
		Recording:     rpc.NewRecordingServer(apiQ, auditLog, recordingPresign, cfg.RecordingURLTTL, authorizer, arSvc),
	}
	if sessionSvc != nil {
		userServices.Session = rpc.NewSessionServer(sessionSvc)
	}
	mux := http.NewServeMux()
	mux.Handle("/", webui.Handler(httpapi.NewRouter(pool, httpapi.RouterDeps{
		Queries:       apiQ,
		Authorizer:    authorizer,
		Getter:        castGetter,
		GrantReviewer: arSvc,
		Validate:      apiLookup.Validate,
		Load:          apiLookup.Load,
	})))
	rpc.RegisterUserServices(mux, userServices)

	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           webcors.New(cfg.DevCORSOrigins)(mux),
		Protocols:         &protos,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Second, mTLS "mesh" listener: serves Dataplane + Gateway to workers/gateway.
	// Peer identity is the mTLS client cert URI SAN (mesh.Middleware). Degraded boot:
	// if MESH_LISTEN_ADDR is unset or the cert files are missing/unreadable, warden
	// logs a warning and serves only the user API (workers/gateway cannot connect).
	meshSrv := buildMeshServer(cfg, pool, setupSvc, registry, sessionPubKey, terminator)

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
func buildMeshServer(cfg config.Config, pool *pgxpool.Pool, setupSvc *dataplane.SetupService, registry *dataplane.Registry, sessionPubKey ed25519.PublicKey, terminator *dataplane.Terminator) *http.Server {
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
	meshServices := rpc.MeshServices{Gateway: rpc.NewGatewayServer(registry, sessionPubKey)}
	if setupSvc != nil {
		meshServices.Dataplane = rpc.NewDataplaneServer(setupSvc, registry, pool, terminator)
	}
	rpc.RegisterMeshServices(meshMux, meshServices)
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
