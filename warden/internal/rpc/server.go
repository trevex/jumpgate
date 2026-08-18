// Package rpc assembles warden's ConnectRPC handlers.
package rpc

import (
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/validate"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/approval/v1/approvalv1connect"
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
	roles := authz.NewRoleResolver(pool)
	catPath, catHandler := catalogv1connect.NewCatalogServiceHandler(NewCatalogServer(q, authorizer, roles), opts)
	mux.Handle(catPath, catHandler)

	resolver := approvals.New(pool)
	apPath, apHandler := approvalv1connect.NewApprovalServiceHandler(NewApprovalServer(q, resolver), opts)
	mux.Handle(apPath, apHandler)

	return nil
}
