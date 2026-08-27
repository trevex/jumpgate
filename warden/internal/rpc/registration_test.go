package rpc_test

import (
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/internal/access"
	"github.com/trevex/jumpgate/warden/internal/accessrequest"
	"github.com/trevex/jumpgate/warden/internal/apiguard"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/audit"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/dataplane"
	"github.com/trevex/jumpgate/warden/internal/gateway"
	"github.com/trevex/jumpgate/warden/internal/identity"
	"github.com/trevex/jumpgate/warden/internal/postgres/sqlc"
	"github.com/trevex/jumpgate/warden/internal/recording"
	"github.com/trevex/jumpgate/warden/internal/rpc"
	"github.com/trevex/jumpgate/warden/internal/secrets"
	"github.com/trevex/jumpgate/warden/internal/session"
	"github.com/trevex/jumpgate/warden/internal/vault"
)

func testUserServices(pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, presigner recording.Presigner, recordingURLTTL time.Duration, cookieSecure bool) rpc.UserServices {
	q := sqlc.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}
	authorizer := authz.New(pool)
	roles := authz.NewRoleResolver(pool)
	resolver := approvals.New(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	services := rpc.UserServices{
		Lookup:        lookup,
		Auth:          auth.NewHandler(q, tokens, authorizer, cookieSecure),
		Identity:      identity.NewHandler(identity.NewService(pool, arSvc, terminator, authorizer), apiguard.New(authorizer, q)),
		Catalog:       catalog.NewHandler(catalog.NewService(pool, sealer, terminator, authorizer, arSvc), apiguard.New(authorizer, q)),
		Access:        access.NewHandler(access.NewService(pool, roles, authorizer, arSvc, arSvc), apiguard.New(authorizer, q)),
		AccessRequest: accessrequest.NewHandler(resolver, arSvc, authorizer, q),
		Vault:         vault.NewHandler(q, sealer, authorizer),
		Recording:     recording.NewHandler(q, auditLog, presigner, recordingURLTTL, authorizer, arSvc),
	}
	if sessionSvc != nil {
		services.Session = session.NewHandler(sessionSvc)
	}
	return services
}

func registerUserServices(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, presigner recording.Presigner, recordingURLTTL time.Duration, cookieSecure bool) error {
	rpc.RegisterUserServices(mux, testUserServices(pool, arSvc, sealer, auditLog, sessionSvc, presigner, recordingURLTTL, cookieSecure))
	return nil
}

func registerMeshServices(mux *http.ServeMux, pool *pgxpool.Pool, auditLog *audit.Logger, setupSvc *dataplane.SetupService, registry *dataplane.Registry, pubKey ed25519.PublicKey) error {
	authorizer := authz.New(pool)
	terminator := dataplane.NewTerminator(pool, authorizer, auditLog)
	services := rpc.MeshServices{Gateway: gateway.NewHandler(registry, pubKey)}
	if setupSvc != nil {
		services.Dataplane = dataplane.NewHandler(setupSvc, registry, pool, terminator)
	}
	rpc.RegisterMeshServices(mux, services)
	return nil
}

func registerServices(mux *http.ServeMux, pool *pgxpool.Pool, arSvc *accessrequest.Service, sealer *secrets.Sealer, auditLog *audit.Logger, sessionSvc *session.Service, setupSvc *dataplane.SetupService, registry *dataplane.Registry, presigner recording.Presigner, recordingURLTTL time.Duration, cookieSecure bool) error {
	if err := registerUserServices(mux, pool, arSvc, sealer, auditLog, sessionSvc, presigner, recordingURLTTL, cookieSecure); err != nil {
		return err
	}
	return registerMeshServices(mux, pool, auditLog, setupSvc, registry, nil)
}
