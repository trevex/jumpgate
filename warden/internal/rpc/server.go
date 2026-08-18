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
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/internal/approvals"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/authz"
	"github.com/trevex/jumpgate/warden/internal/db/gen"
)

// Register mounts all warden RPC services onto mux with auth + validation interceptors.
func Register(mux *http.ServeMux, pool *pgxpool.Pool) error {
	q := gen.New(pool)
	tokens := auth.NewTokenService(q)
	lookup := auth.Lookup{Tokens: tokens, Q: q}

	validator := validate.NewInterceptor()
	opts := connect.WithInterceptors(auth.NewInterceptor(lookup), validator)

	authPath, authHandler := authv1connect.NewAuthServiceHandler(NewAuthServer(q, tokens), opts)
	mux.Handle(authPath, authHandler)

	idPath, idHandler := identityv1connect.NewIdentityServiceHandler(NewIdentityServer(q, tokens), opts)
	mux.Handle(idPath, idHandler)

	authorizer := authz.NewSQLAuthorizer(pool)
	catPath, catHandler := catalogv1connect.NewCatalogServiceHandler(NewCatalogServer(q, authorizer), opts)
	mux.Handle(catPath, catHandler)

	roles := authz.NewRoleResolver(pool)
	accessPath, accessHandler := accessv1connect.NewAccessServiceHandler(NewAccessServer(q, roles), opts)
	mux.Handle(accessPath, accessHandler)

	resolver := approvals.New(pool)
	arPath, arHandler := accessrequestv1connect.NewAccessRequestServiceHandler(NewAccessRequestServer(resolver), opts)
	mux.Handle(arPath, arHandler)

	return nil
}
