// Package meshclient builds the k8s-broker's connect-go client to warden over
// the SPIFFE-pinned mesh mTLS transport.
package meshclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	gatewayv1 "github.com/trevex/jumpgate/warden/gen/jumpgate/gateway/v1"
	"github.com/trevex/jumpgate/warden/gen/jumpgate/gateway/v1/gatewayv1connect"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/mesh"
)

// New builds a DataplaneService connect-go client over a SPIFFE-pinned mesh mTLS
// HTTP/2 transport to warden.
func New(wardenAddr string, leaf tls.Certificate, pool *x509.CertPool, wardenSpiffe string) dataplanev1connect.DataplaneServiceClient {
	tlsCfg := mesh.ClientTLSConfig(leaf, pool, wardenSpiffe)
	tr := &http2.Transport{
		TLSClientConfig: tlsCfg,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &tls.Dialer{Config: cfg}
			return d.DialContext(ctx, network, addr)
		},
	}
	httpClient := &http.Client{Transport: tr}
	// WARDEN_MESH_ADDR already carries the https:// scheme (shared Helm convention);
	// only add it when absent so we never produce a double scheme (https://https://…),
	// which connect-go dials as host "https" → "write envelope: EOF".
	baseURL := wardenAddr
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	return dataplanev1connect.NewDataplaneServiceClient(httpClient, baseURL, connect.WithGRPC())
}

// FetchVerificationKey retrieves warden's Ed25519 session-token public key over
// the same mesh mTLS transport used for the control loop, retrying briefly so a
// broker that races warden's boot still comes up. Returns the raw public key bytes.
func FetchVerificationKey(ctx context.Context, wardenAddr string, leaf tls.Certificate, pool *x509.CertPool, wardenSpiffe string) ([]byte, error) {
	tlsCfg := mesh.ClientTLSConfig(leaf, pool, wardenSpiffe)
	tr := &http2.Transport{
		TLSClientConfig: tlsCfg,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &tls.Dialer{Config: cfg}
			return d.DialContext(ctx, network, addr)
		},
	}
	httpClient := &http.Client{Transport: tr}
	baseURL := wardenAddr
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	client := gatewayv1connect.NewGatewayServiceClient(httpClient, baseURL, connect.WithGRPC())

	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		resp, err := client.GetSessionVerificationKey(ctx, connect.NewRequest(&gatewayv1.GetSessionVerificationKeyRequest{}))
		if err == nil {
			return resp.Msg.GetEd25519PublicKey(), nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, fmt.Errorf("fetch verification key: %w", lastErr)
}
