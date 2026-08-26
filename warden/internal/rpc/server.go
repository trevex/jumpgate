// Package rpc assembles warden's ConnectRPC handlers.
package rpc

import (
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/validate"

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
	"github.com/trevex/jumpgate/warden/internal/access"
	"github.com/trevex/jumpgate/warden/internal/auth"
	"github.com/trevex/jumpgate/warden/internal/catalog"
	"github.com/trevex/jumpgate/warden/internal/identity"
)

// UserServices is the complete set of already-constructed user-facing Connect
// adapters. Application wiring belongs to internal/app; registration only mounts
// handlers and transport interceptors.
type UserServices struct {
	Lookup        auth.Lookup
	Auth          *AuthServer
	Identity      *identity.Handler
	Catalog       *catalog.Handler
	Access        *access.Handler
	AccessRequest *AccessRequestServer
	Vault         *VaultServer
	Recording     *RecordingServer
	Session       *SessionServer // optional when session admission is disabled
}

// RegisterUserServices mounts the bearer-authenticated user services.
func RegisterUserServices(mux *http.ServeMux, services UserServices) {
	validator := validate.NewInterceptor()
	opts := connect.WithInterceptors(auth.NewInterceptor(services.Lookup), validator)

	authPath, authHandler := authv1connect.NewAuthServiceHandler(services.Auth, opts)
	mux.Handle(authPath, authHandler)

	idPath, idHandler := identityv1connect.NewIdentityServiceHandler(services.Identity, opts)
	mux.Handle(idPath, idHandler)

	catPath, catHandler := catalogv1connect.NewCatalogServiceHandler(services.Catalog, opts)
	mux.Handle(catPath, catHandler)

	accessPath, accessHandler := accessv1connect.NewAccessServiceHandler(services.Access, opts)
	mux.Handle(accessPath, accessHandler)

	arPath, arHandler := accessrequestv1connect.NewAccessRequestServiceHandler(services.AccessRequest, opts)
	mux.Handle(arPath, arHandler)

	vaultPath, vaultHandler := vaultv1connect.NewVaultServiceHandler(services.Vault, opts)
	mux.Handle(vaultPath, vaultHandler)

	recPath, recHandler := recordingv1connect.NewRecordingServiceHandler(services.Recording, opts)
	mux.Handle(recPath, recHandler)

	if services.Session != nil {
		sPath, sHandler := sessionv1connect.NewSessionServiceHandler(services.Session, opts)
		mux.Handle(sPath, sHandler)
	}

}

// MeshServices is the complete set of already-constructed mesh-facing adapters.
type MeshServices struct {
	Gateway   *GatewayServer
	Dataplane *DataplaneServer // optional when session setup is disabled
}

// RegisterMeshServices mounts the mTLS-authenticated worker/gateway services.
func RegisterMeshServices(mux *http.ServeMux, services MeshServices) {
	validator := validate.NewInterceptor()
	opts := connect.WithInterceptors(validator)

	gwPath, gwHandler := gatewayv1connect.NewGatewayServiceHandler(services.Gateway, opts)
	mux.Handle(gwPath, gwHandler)

	if services.Dataplane != nil {
		dPath, dHandler := dataplanev1connect.NewDataplaneServiceHandler(services.Dataplane, opts)
		mux.Handle(dPath, dHandler)
	}

}
