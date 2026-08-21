// Package rpc assembles warden's ConnectRPC handlers.
package rpc

import (
	"net/http"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/gateway/v1/gatewayv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1/recordingv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
)

// RegisterUserServices mounts the USER-facing (bearer-authed) RPC services onto
// mux with the auth + validation interceptors: Auth, Identity, Catalog, Access,
// AccessRequest, Vault, and (when available) Session. These serve on warden's
// existing HTTP bearer-token listener.
//
// arSvc is the shared access-request Service (its terminator + audit are also used
// by the expiry reaper, so caller builds it ONCE and shares it).
//
// sealer is the vault sealer built once at startup; a nil sealer means the vault
// is disabled (VaultService still mounts, but its sealing write paths fail
// FailedPrecondition).
//
// sessionSvc is the CLI-facing data-plane admission service. It is nil when the
// vault or the active session signing key is unavailable; in that case
// SessionService is not mounted (CreateSession is disabled until initialized).
//
// recordingPresign issues short-lived presigned download URLs for session
// recordings; a nil presigner makes RecordingService's download path fail closed
// (FailedPrecondition). recordingURLTTL bounds the lifetime of an issued URL.
func RegisterUserServices(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, sessionSvc *session.Service, recordingPresign Presigner, recordingURLTTL time.Duration) error {
	q := gen.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}

	validator := validate.NewInterceptor()
	opts := connect.WithInterceptors(auth.NewInterceptor(lookup), validator)

	roles := authz.NewRoleResolver(pool)
	resolver := approvals.New(pool)
	authorizer := authz.NewSQLAuthorizer(pool)

	authPath, authHandler := authv1connect.NewAuthServiceHandler(NewAuthServer(q, tokens, authorizer, true /* TODO: cfg.CookieSecure (Task 5) */), opts)
	mux.Handle(authPath, authHandler)

	// A standalone terminator (stateless; a second instance alongside the mesh
	// side is fine) lets DeactivateUser synchronously evict a user's live
	// sessions as part of the API call.
	terminator := dataplane.NewTerminator(pool, authz.NewSQLAuthorizer(pool), audit.New(pool))
	idPath, idHandler := identityv1connect.NewIdentityServiceHandler(NewIdentityServer(q, tokens, arSvc, terminator, authorizer), opts)
	mux.Handle(idPath, idHandler)

	catPath, catHandler := catalogv1connect.NewCatalogServiceHandler(NewCatalogServer(q, pool, authorizer), opts)
	mux.Handle(catPath, catHandler)

	accessPath, accessHandler := accessv1connect.NewAccessServiceHandler(NewAccessServer(q, roles, authorizer), opts)
	mux.Handle(accessPath, accessHandler)

	arPath, arHandler := accessrequestv1connect.NewAccessRequestServiceHandler(NewAccessRequestServer(resolver, arSvc, authorizer, q), opts)
	mux.Handle(arPath, arHandler)

	vaultPath, vaultHandler := vaultv1connect.NewVaultServiceHandler(NewVaultServer(q, sealer, authorizer), opts)
	mux.Handle(vaultPath, vaultHandler)

	recPath, recHandler := recordingv1connect.NewRecordingServiceHandler(NewRecordingServer(q, audit.New(pool), recordingPresign, recordingURLTTL, authorizer), opts)
	mux.Handle(recPath, recHandler)

	if sessionSvc != nil {
		sPath, sHandler := sessionv1connect.NewSessionServiceHandler(NewSessionServer(sessionSvc), opts)
		mux.Handle(sPath, sHandler)
	}

	return nil
}

// RegisterMeshServices mounts the WORKER/GATEWAY-facing RPC services onto mux with
// the validation interceptor ONLY: Dataplane + Gateway. These serve on warden's
// second, mTLS "mesh" listener; there is no bearer auth here — peer identity comes
// from the mTLS client cert's URI SAN (via mesh.Middleware) and the handlers derive
// the authoritative worker_id from it.
//
// setupSvc backs the data-plane worker RPCs (SetupSession + WorkerStream). If it is
// nil (vault/active-key unavailable), DataplaneService is not mounted. registry is
// the in-memory worker registry shared with the terminator/listener so teardown can
// be pushed to the owning stream. gatewaySvc backs the gateway-facing roster +
// verification-key RPCs and is always mounted.
func RegisterMeshServices(mux *http.ServeMux, pool *pgxpool.Pool, auditLog *audit.Logger, setupSvc *dataplane.SetupService, registry *dataplane.Registry, gatewaySvc *GatewayServer) error {
	validator := validate.NewInterceptor()
	opts := connect.WithInterceptors(validator)

	gwPath, gwHandler := gatewayv1connect.NewGatewayServiceHandler(gatewaySvc, opts)
	mux.Handle(gwPath, gwHandler)

	if setupSvc != nil {
		terminator := dataplane.NewTerminator(pool, authz.NewSQLAuthorizer(pool), auditLog)
		dPath, dHandler := dataplanev1connect.NewDataplaneServiceHandler(NewDataplaneServer(setupSvc, registry, pool, terminator), opts)
		mux.Handle(dPath, dHandler)
	}

	return nil
}

// Register mounts BOTH the user-facing and mesh-facing services onto a single mux.
// It is a convenience for tests that only exercise the user (bearer) services and
// do not need the mTLS identity split; production (main.go) and the mesh identity
// tests use RegisterUserServices / RegisterMeshServices on separate muxes. The
// GatewayServer here carries no session verification key (its GetSessionVerification
// Key returns FailedPrecondition), which is acceptable for the user-only tests.
func Register(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, setupSvc *dataplane.SetupService, registry *dataplane.Registry, recordingPresign Presigner, recordingURLTTL time.Duration) error {
	if err := RegisterUserServices(mux, pool, arSvc, sealer, sessionSvc, recordingPresign, recordingURLTTL); err != nil {
		return err
	}
	return RegisterMeshServices(mux, pool, auditLog, setupSvc, registry, NewGatewayServer(registry, nil))
}
