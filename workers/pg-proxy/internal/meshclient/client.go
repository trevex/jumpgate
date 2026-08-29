// Package meshclient builds the pg-proxy worker's connect-go client to warden
// over the SPIFFE-pinned mesh mTLS transport.
package meshclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/mesh"
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
	return dataplanev1connect.NewDataplaneServiceClient(httpClient, "https://"+wardenAddr, connect.WithGRPC())
}
