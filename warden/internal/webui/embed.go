//go:build embedui

package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the embedded SPA: real files from dist/, and any other GET that
// isn't a backend route falls back to index.html so client-side routes deep-link.
// Non-GET and known backend paths (RPC, /healthz) delegate to next.
func Handler(next http.Handler) http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	index, _ := fs.ReadFile(sub, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || strings.HasPrefix(r.URL.Path, "/jumpgate.") || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if p := strings.TrimPrefix(r.URL.Path, "/"); p != "" {
			if _, err := fs.Stat(sub, p); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
