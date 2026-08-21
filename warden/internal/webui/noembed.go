//go:build !embedui

// Package webui serves the embedded SPA when built with -tags embedui. In the
// default build it is a no-op passthrough, so `go build`/tests need no frontend.
package webui

import "net/http"

// Handler returns next unchanged: the SPA is served by Vite in dev.
func Handler(next http.Handler) http.Handler { return next }
