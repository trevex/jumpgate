// Command pg-proxy is jumpgate's PostgreSQL data-plane worker: it registers with
// warden over the mesh and (in a later plan) proxies pgwire sessions to Postgres
// targets.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trevex/jumpgate/workers/pg-proxy/internal/config"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/control"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/mesh"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/meshclient"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	leaf, pool, err := mesh.LoadKeyPair(cfg.MeshCertFile, cfg.MeshKeyFile, cfg.MeshCAFile)
	if err != nil {
		slog.Error("mesh certs", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go serveHealth(cfg.HealthAddr)

	client := meshclient.New(cfg.WardenMeshAddr, leaf, pool, cfg.WardenSpiffe)
	reg := control.NewRegistry()
	ended := make(chan control.SessionEnd, 16) // wired to the data-plane path in a later plan
	slog.Info("pg-proxy starting", "worker_id", cfg.WorkerID, "warden", cfg.WardenMeshAddr, "dataplane", cfg.DataplaneAddr)
	// TODO(pg-proxy Plan B2): start the gateway-facing data-plane listener here
	// (mesh.ServerTLSConfig + mesh.ReadConnect + client.SetupSession + pgwire proxy),
	// registering each session's cancel in reg and pushing control.SessionEnd to `ended`.
	if err := control.Run(ctx, client, reg, control.RunConfig{
		WorkerID:         cfg.WorkerID,
		DataplaneAddress: cfg.DataplaneAddr,
		Capacity:         cfg.Capacity,
		Protocols:        []string{"postgres"},
	}, ended); err != nil && ctx.Err() == nil {
		slog.Error("control loop", "err", err)
		os.Exit(1)
	}
}

// serveHealth accepts plaintext HTTP on addr and 200s every request for kubelet
// liveness/readiness probes.
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
