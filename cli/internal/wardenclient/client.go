// Package wardenclient wraps the bearer-authed warden ConnectRPC clients the
// CLI needs to resolve assets and open sessions.
package wardenclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	catalogv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/catalog/v1/catalogv1connect"
	sessionv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/session/v1/sessionv1connect"
)

// Client wraps the warden ConnectRPC clients the CLI uses. Every request is
// authenticated with the configured bearer token.
type Client struct {
	token   string
	catalog catalogv1connect.CatalogServiceClient
	session sessionv1connect.SessionServiceClient
}

// New builds a Client for the warden at addr, authenticating with token. The
// underlying HTTP client mirrors login.go: for a plaintext http:// address it
// enables unencrypted HTTP/2 (h2c) alongside HTTP/1.1; https:// uses defaults.
func New(addr, token string) *Client {
	httpc := httpClient(addr)
	return &Client{
		token:   token,
		catalog: catalogv1connect.NewCatalogServiceClient(httpc, addr),
		session: sessionv1connect.NewSessionServiceClient(httpc, addr),
	}
}

// ResolveAsset maps an exact asset name to its id via ListVisibleAssets. If name
// already parses as a UUID it is returned as-is. A missing name or an ambiguous
// match (two visible assets sharing the name) is an error.
func (c *Client) ResolveAsset(ctx context.Context, name string) (string, error) {
	if _, err := uuid.Parse(name); err == nil {
		return name, nil
	}

	req := connect.NewRequest(&catalogv1.ListVisibleAssetsRequest{})
	c.authorize(req)
	resp, err := c.catalog.ListVisibleAssets(ctx, req)
	if err != nil {
		return "", fmt.Errorf("listing assets: %w", err)
	}

	var match string
	for _, a := range resp.Msg.GetAssets() {
		if a.GetName() != name {
			continue
		}
		if match != "" {
			return "", fmt.Errorf("asset name %q is ambiguous", name)
		}
		match = a.GetId()
	}
	if match == "" {
		return "", fmt.Errorf("no asset named %q", name)
	}
	return match, nil
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
