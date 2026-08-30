// Package proxy is the k8s-agent's request forwarder: it rewrites tunneled
// requests onto the local API server, adding the agent's ServiceAccount bearer
// and preserving the caller's Impersonate-* headers.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Handler forwards requests to a Kubernetes API server as the agent's SA.
type Handler struct {
	target      *url.URL
	client      *http.Client
	saTokenFile string
}

// New builds a Handler that dials apiServerURL, trusting caCertFile, and reads
// the SA bearer token fresh from saTokenFile on each request (so kubelet token
// rotation is picked up).
func New(apiServerURL, caCertFile, saTokenFile string) (*Handler, error) {
	target, err := url.Parse(apiServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse api server url: %w", err)
	}
	caPEM, err := os.ReadFile(caCertFile) //nolint:gosec // trusted env path
	if err != nil {
		return nil, fmt.Errorf("read api server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certs in api server CA bundle")
	}
	return &Handler{
		target:      target,
		saTokenFile: saTokenFile,
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		}},
	}, nil
}

// hopByHop headers must not be forwarded.
var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

// ServeHTTP forwards r to the API server. It replaces any client Authorization
// with the agent's SA bearer and leaves Impersonate-* headers (set upstream by
// the broker from the verified identity) intact.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := os.ReadFile(h.saTokenFile) //nolint:gosec // trusted env path
	if err != nil {
		http.Error(w, "read sa token", http.StatusInternalServerError)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = h.target.Scheme
	out.URL.Host = h.target.Host
	out.Host = h.target.Host
	for k := range hopByHop {
		out.Header.Del(k)
	}
	out.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := h.client.Do(out)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
