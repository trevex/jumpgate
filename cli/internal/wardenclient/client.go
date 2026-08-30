// Package wardenclient wraps the bearer-authed warden ConnectRPC clients the
// CLI needs to resolve assets and open sessions.
package wardenclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/access/v1/accessv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/accessrequest/v1/accessrequestv1connect"
	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	enrollmentv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/enrollment/v1/enrollmentv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/identity/v1/identityv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/recording/v1/recordingv1connect"
	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/vault/v1/vaultv1connect"
)

// Client wraps the warden ConnectRPC clients the CLI uses. Every request is
// authenticated with the configured bearer token.
type Client struct {
	token         string
	catalog       catalogv1connect.CatalogServiceClient
	session       sessionv1connect.SessionServiceClient
	identity      identityv1connect.IdentityServiceClient
	access        accessv1connect.AccessServiceClient
	accessRequest accessrequestv1connect.AccessRequestServiceClient
	recording     recordingv1connect.RecordingServiceClient
	vault         vaultv1connect.VaultServiceClient
	enrollment    enrollmentv1connect.EnrollmentServiceClient
}

// New builds a Client for the warden at addr, authenticating with token. The
// underlying HTTP client mirrors login.go: for a plaintext http:// address it
// enables unencrypted HTTP/2 (h2c) alongside HTTP/1.1; https:// uses defaults.
func New(addr, token string) *Client {
	httpc := httpClient(addr)
	return &Client{
		token:         token,
		catalog:       catalogv1connect.NewCatalogServiceClient(httpc, addr),
		session:       sessionv1connect.NewSessionServiceClient(httpc, addr),
		identity:      identityv1connect.NewIdentityServiceClient(httpc, addr),
		access:        accessv1connect.NewAccessServiceClient(httpc, addr),
		accessRequest: accessrequestv1connect.NewAccessRequestServiceClient(httpc, addr),
		recording:     recordingv1connect.NewRecordingServiceClient(httpc, addr),
		vault:         vaultv1connect.NewVaultServiceClient(httpc, addr),
		enrollment:    enrollmentv1connect.NewEnrollmentServiceClient(httpc, addr),
	}
}

// Catalog returns the catalog service client.
func (c *Client) Catalog() catalogv1connect.CatalogServiceClient { return c.catalog }

// Identity returns the identity service client.
func (c *Client) Identity() identityv1connect.IdentityServiceClient { return c.identity }

// Access returns the access service client.
func (c *Client) Access() accessv1connect.AccessServiceClient { return c.access }

// AccessRequest returns the access request service client.
func (c *Client) AccessRequest() accessrequestv1connect.AccessRequestServiceClient {
	return c.accessRequest
}

// Recording returns the recording service client.
func (c *Client) Recording() recordingv1connect.RecordingServiceClient { return c.recording }

// Vault returns the vault service client.
func (c *Client) Vault() vaultv1connect.VaultServiceClient { return c.vault }

// Authorize attaches the bearer token to any connect request. Command files
// build their own typed requests and call this before sending.
func (c *Client) Authorize(req interface{ Header() http.Header }) { c.authorize(req) }

// ResolveAsset maps a uuid or DNS-style path ref to an asset id. A uuid short-circuits
// locally (no round-trip); anything else is resolved by warden, which checks access +
// existence (a bad ref or no access surfaces as NotFound).
func (c *Client) ResolveAsset(ctx context.Context, ref string) (string, error) {
	if _, err := uuid.Parse(ref); err == nil {
		return ref, nil
	}
	req := connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: ref})
	c.authorize(req)
	resp, err := c.catalog.ResolveAsset(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Msg.GetAssetId(), nil
}

// CreateSession requests admission to assetID with the ephemeral client public
// key kcPub. It returns the session token and the gateway endpoint to dial. A
// NotFound from warden (existence-hiding) is reported as no access.
func (c *Client) CreateSession(ctx context.Context, assetID string, kcPub []byte) (token, gatewayEndpoint string, err error) {
	req := connect.NewRequest(&sessionv1.CreateSessionRequest{
		AssetId:            assetID,
		ClientSshPublicKey: kcPub,
	})
	c.authorize(req)
	resp, err := c.session.CreateSession(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return "", "", errors.New("no access to asset")
		}
		return "", "", fmt.Errorf("creating session: %w", err)
	}
	return resp.Msg.GetSessionToken(), resp.Msg.GetGatewayEndpoint(), nil
}

// ResolveAssetInfo maps a uuid or DNS-style path ref to an asset id AND its kind.
// Unlike ResolveAsset it always round-trips (even for a uuid) because the caller
// needs the kind to choose a connect strategy. NotFound (existence-hiding) surfaces
// as a wrapped error.
func (c *Client) ResolveAssetInfo(ctx context.Context, ref string) (assetID, kind string, err error) {
	req := connect.NewRequest(&catalogv1.ResolveAssetRequest{Ref: ref})
	c.authorize(req)
	resp, err := c.catalog.ResolveAsset(ctx, req)
	if err != nil {
		return "", "", err
	}
	return resp.Msg.GetAssetId(), resp.Msg.GetKind(), nil
}

// CreatePostgresSession requests admission to a postgres asset as the given DB
// role. It returns the bearer session token, the gateway endpoint to dial, and the
// asset's default database (for the connection hint). NotFound → no access.
func (c *Client) CreatePostgresSession(ctx context.Context, assetID, role string) (token, gatewayEndpoint, defaultDB string, err error) {
	req := connect.NewRequest(&sessionv1.CreatePostgresSessionRequest{AssetId: assetID, Login: role})
	c.authorize(req)
	resp, err := c.session.CreatePostgresSession(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return "", "", "", errors.New("no access to asset")
		}
		return "", "", "", fmt.Errorf("creating postgres session: %w", err)
	}
	return resp.Msg.GetSessionToken(), resp.Msg.GetGatewayEndpoint(), resp.Msg.GetDefaultDatabase(), nil
}

// CreateKubernetesSession requests admission to a k8s asset. It returns the bearer
// session token, the gateway endpoint to dial, and the token's expiry. NotFound → no access.
func (c *Client) CreateKubernetesSession(ctx context.Context, assetID string) (token, gatewayEndpoint string, expiresAt time.Time, err error) {
	req := connect.NewRequest(&sessionv1.CreateKubernetesSessionRequest{AssetId: assetID})
	c.authorize(req)
	resp, err := c.session.CreateKubernetesSession(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return "", "", time.Time{}, errors.New("no access to asset")
		}
		return "", "", time.Time{}, fmt.Errorf("creating kubernetes session: %w", err)
	}
	return resp.Msg.GetSessionToken(), resp.Msg.GetGatewayEndpoint(), resp.Msg.GetExpiresAt().AsTime(), nil
}

// CreateEnrollmentToken mints a single-use enrollment token bound to assetID
// (admin-only; requires catalog:asset:update on the asset).
func (c *Client) CreateEnrollmentToken(ctx context.Context, assetID string) (token, expiresAt string, err error) {
	req := connect.NewRequest(&enrollmentv1.CreateEnrollmentTokenRequest{AssetId: assetID})
	c.authorize(req)
	resp, err := c.enrollment.CreateEnrollmentToken(ctx, req)
	if err != nil {
		return "", "", fmt.Errorf("creating enrollment token: %w", err)
	}
	return resp.Msg.GetToken(), resp.Msg.GetExpiresAt(), nil
}

// authorize sets the bearer token on a request.
func (c *Client) authorize(req interface{ Header() http.Header }) {
	req.Header().Set("Authorization", "Bearer "+c.token)
}

// httpClient returns an HTTP client suited to the given warden address. For a
// plaintext http:// address it enables unencrypted HTTP/2 (h2c) alongside
// HTTP/1.1 so it works whether or not warden negotiates h2c; https:// uses the
// default client.
func httpClient(addr string) connect.HTTPClient {
	if !strings.HasPrefix(addr, "http://") {
		return http.DefaultClient
	}
	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: &protos}}
}
