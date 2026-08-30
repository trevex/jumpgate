// Command k8s-agent runs in a target cluster: it dials the broker over mesh
// mTLS, then serves HTTP/2 on that reverse tunnel, forwarding each request to
// the local API server as its own ServiceAccount.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"

	"github.com/trevex/jumpgate/workers/k8s-agent/internal/config"
	"github.com/trevex/jumpgate/workers/k8s-agent/internal/enroll"
	"github.com/trevex/jumpgate/workers/k8s-agent/internal/mesh"
	"github.com/trevex/jumpgate/workers/k8s-agent/proxy"
)

const reconnectBackoff = 2 * time.Second

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Bootstrap mesh identity if a token is set and no cert exists yet.
	if cfg.EnrollmentToken != "" {
		if _, statErr := os.Stat(cfg.MeshCertFile); os.IsNotExist(statErr) {
			var caPEM []byte
			if cfg.EnrollmentCA != "" {
				caPEM, err = os.ReadFile(cfg.EnrollmentCA)
				if err != nil {
					slog.Error("read enrollment CA", "err", err)
					os.Exit(1)
				}
			}
			slog.Info("enrolling agent", "warden", cfg.WardenEnrollURL)
			if err := enroll.Run(ctx, enroll.Params{
				WardenURL: cfg.WardenEnrollURL, Token: cfg.EnrollmentToken, CAPEM: caPEM,
				CertFile: cfg.MeshCertFile, KeyFile: cfg.MeshKeyFile, CAFile: cfg.MeshCAFile,
			}); err != nil {
				slog.Error("enrollment failed", "err", err)
				os.Exit(1)
			}
			slog.Info("enrollment complete")
		}
	}

	leaf, pool, err := mesh.LoadKeyPair(cfg.MeshCertFile, cfg.MeshKeyFile, cfg.MeshCAFile)
	if err != nil {
		slog.Error("mesh certs", "err", err)
		os.Exit(1)
	}
	handler, err := proxy.New(cfg.APIServerURL, cfg.APIServerCA, cfg.SATokenFile)
	if err != nil {
		slog.Error("proxy", "err", err)
		os.Exit(1)
	}

	go serveHealth(cfg.HealthAddr)

	// Pin the broker by ROLE (any broker id) — the agent may reach any replica via the LB.
	tlsCfg := mesh.ClientTLSConfigRole(leaf, pool, "broker")
	h2 := &http2.Server{}
	for ctx.Err() == nil {
		if err := dialAndServe(ctx, cfg.BrokerAddr, tlsCfg, h2, handler); err != nil && ctx.Err() == nil {
			slog.Warn("tunnel dropped; reconnecting", "err", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(reconnectBackoff):
		}
	}
}

// dialAndServe dials the broker over mesh mTLS and serves HTTP/2 on the conn
// (role-reversed: the agent that dialed acts as the HTTP/2 server). Blocks until
// the conn errors or ctx ends.
func dialAndServe(ctx context.Context, addr string, tlsCfg *tls.Config, h2 *http2.Server, handler http.Handler) error {
	d := &tls.Dialer{Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	slog.Info("tunnel established", "broker", addr)
	h2.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
	return nil
}

func serveHealth(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("health listen", "err", err)
		return
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	_ = srv.Serve(ln)
}
