// Package frontdoor is the k8s-broker's gateway-facing HTTP front door. The
// gateway blind-pipes kubectl's HTTP/1.1 stream here over mesh mTLS; this handler
// verifies the session token, strips any client-supplied identity headers, sets
// Impersonate-* from the token, and forwards to the agent tunnel via RoundTrip.
package frontdoor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
)

// Tunnel is the broker's agent-forwarding seam (satisfied by *broker.Broker).
type Tunnel interface {
	RoundTrip(assetID string, req *http.Request) (*http.Response, error)
}

type ctxKey struct{}

// errNoClaims fails a forward closed if the verified claims are ever missing from
// the request context (unreachable today — the handler always sets them before
// invoking the proxy — but a comma-ok guard beats a panic under future refactors).
var errNoClaims = errors.New("frontdoor: missing verified claims")

// Handler builds the front-door http.Handler. Every request must carry a valid
// kubernetes session token in Authorization: Bearer; identity comes ONLY from the
// verified token, never from client headers.
func Handler(t Tunnel, v *sessiontoken.Verifier) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			claims, ok := pr.In.Context().Value(ctxKey{}).(sessiontoken.Claims)
			if !ok {
				return // no identity set → Transport fails the forward closed
			}
			// The agent rewrites scheme/host to the real API server; any https
			// URL satisfies the h2 tunnel client (see broker RoundTrip).
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = "tunnel"
			// Strip everything the client might use to forge identity.
			pr.Out.Header.Del("Authorization")
			for k := range pr.Out.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(k), "Impersonate-") {
					pr.Out.Header.Del(k)
				}
			}
			// Set identity from the verified token.
			pr.Out.Header.Set("Impersonate-User", claims.UserID.String())
			for _, g := range claims.Groups {
				pr.Out.Header.Add("Impersonate-Group", g)
			}
		},
		Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
			claims, ok := req.Context().Value(ctxKey{}).(sessiontoken.Claims)
			if !ok {
				return nil, errNoClaims
			}
			return t.RoundTrip(claims.AssetID.String(), req)
		}),
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r.Header.Get("Authorization"))
		if tok == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, err := v.Verify(tok)
		if err != nil || claims.Protocol != "kubernetes" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, claims)
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearer extracts the token from an "Authorization: Bearer <t>" value.
func bearer(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
