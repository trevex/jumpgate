// Package probe performs the k8s-agent's local, credential-free API-server
// identity observation: a TLS handshake to the bound API server that captures the
// presented certificate chain and stops. It never reads the ServiceAccount token —
// identity observation and credential use are strictly separated (the SA token is
// read only on the forward path in the proxy package).
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
)

// Evidence is the API-server identity a local probe observed: the server name it
// connected to (SNI) and the certificate chain the server presented, leaf-first,
// as raw DER. It deliberately carries no ServiceAccount token.
type Evidence struct {
	ServerName string
	ChainDER   [][]byte
}

// Probe performs a TLS handshake to the API server at apiServerURL and returns the
// presented certificate chain. It does NOT verify the chain (warden decides trust
// via approved anchors, from the returned evidence) and NEVER reads the
// ServiceAccount token: the handshake stops before any credential-bearing request.
func Probe(ctx context.Context, apiServerURL string) (Evidence, error) {
	u, err := url.Parse(apiServerURL)
	if err != nil {
		return Evidence{}, fmt.Errorf("parse api server url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return Evidence{}, fmt.Errorf("api server url has no host: %q", apiServerURL)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(host, "443")
	}
	d := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// Observation only: warden authenticates the target against operator-approved
		// anchors using the chain captured here, not this handshake's verification.
		InsecureSkipVerify: true, //nolint:gosec // see above — trust is decided by warden anchors
	}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Evidence{}, fmt.Errorf("tls dial api server: %w", err)
	}
	defer func() { _ = conn.Close() }()
	state := conn.(*tls.Conn).ConnectionState()
	chain := make([][]byte, 0, len(state.PeerCertificates))
	for _, c := range state.PeerCertificates {
		chain = append(chain, c.Raw)
	}
	if len(chain) == 0 {
		return Evidence{}, fmt.Errorf("api server presented no certificate")
	}
	return Evidence{ServerName: host, ChainDER: chain}, nil
}
