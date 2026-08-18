// Package rpc assembles warden's ConnectRPC handlers.
package rpc

import (
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/auth/v1/authv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
)

// Register mounts all warden RPC services onto mux with auth + validation
// interceptors. arSvc is the shared access-request Service (its terminator + audit
// are also used by the expiry reaper, so caller builds it ONCE and shares it).
//
// sealer is the vault sealer built once at startup; a nil sealer means the vault
// is disabled (VaultService still mounts, but its sealing write paths fail
// FailedPrecondition). The CredentialBroker is wired in M4 — VaultService is the
// only vault surface mounted here.
//
// sessionSvc is the CLI-facing data-plane admission service. It is nil when the
// vault or the active session signing key is unavailable; in that case
// SessionService is not mounted (CreateSession is disabled until initialized).
//
// setupSvc backs the data-plane worker RPCs (SetupSession + WorkerStream); it is
// nil under the same conditions as sessionSvc, in which case DataplaneService is
// not mounted. registry is the in-memory worker registry shared with the (later)
// terminator/listener so teardown can be pushed to the owning stream.
func Register(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, sessionSvc *session.Service, setupSvc *dataplane.SetupService, registry *dataplane.Registry) error {
	q := gen.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}

	validator := validate.NewInterceptor()
	opts := connect.WithInterceptors(auth.NewInterceptor(lookup), validator)

	authPath, authHandler := authv1connect.NewAuthServiceHandler(NewAuthServer(q, tokens), opts)
	mux.Handle(authPath, authHandler)

	roles := authz.NewRoleResolver(pool)
	resolver := approvals.New(pool)

	idPath, idHandler := identityv1connect.NewIdentityServiceHandler(NewIdentityServer(q, tokens, arSvc), opts)
	mux.Handle(idPath, idHandler)

	authorizer := authz.NewSQLAuthorizer(pool)
	catPath, catHandler := catalogv1connect.NewCatalogServiceHandler(NewCatalogServer(q, authorizer), opts)
	mux.Handle(catPath, catHandler)

	accessPath, accessHandler := accessv1connect.NewAccessServiceHandler(NewAccessServer(q, roles), opts)
	mux.Handle(accessPath, accessHandler)

	arPath, arHandler := accessrequestv1connect.NewAccessRequestServiceHandler(NewAccessRequestServer(resolver, arSvc), opts)
	mux.Handle(arPath, arHandler)

	vaultPath, vaultHandler := vaultv1connect.NewVaultServiceHandler(NewVaultServer(q, sealer), opts)
	mux.Handle(vaultPath, vaultHandler)

	if sessionSvc != nil {
		sPath, sHandler := sessionv1connect.NewSessionServiceHandler(NewSessionServer(sessionSvc), opts)
		mux.Handle(sPath, sHandler)
	}

	if setupSvc != nil {
		dPath, dHandler := dataplanev1connect.NewDataplaneServiceHandler(NewDataplaneServer(setupSvc, registry, pool), opts)
		mux.Handle(dPath, dHandler)
	}

	return nil
}
