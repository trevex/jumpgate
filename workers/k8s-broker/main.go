// Command k8s-broker accepts agent reverse tunnels over mesh mTLS. Each agent
// dials in and becomes an HTTP/2 server on that conn; the broker is the HTTP/2
// client and holds one tunnel per asset id, exposing RoundTrip(assetID, req).
// The gateway-facing side that calls RoundTrip lands in a later slice.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trevex/jumpgate/workers/k8s-broker/internal/broker"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/config"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/control"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/frontdoor"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/mesh"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/meshclient"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/record"
	"github.com/trevex/jumpgate/workers/k8s-broker/internal/sessiontoken"
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

	// Accept agent tunnels: pin the client ROLE to "agent" (any asset id).
	ln, err := tls.Listen("tcp", cfg.AgentListen, mesh.ServerTLSConfigRole(leaf, pool, "agent"))
	if err != nil {
		slog.Error("agent listen", "err", err)
		os.Exit(1)
	}
	slog.Info("k8s-broker accepting agent tunnels", "addr", cfg.AgentListen)
	b := broker.New()
	go func() {
		if err := b.Serve(ctx, ln); err != nil {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	}()

	// Front door: the gateway forwards kubectl's HTTP/1.1 stream here over mesh
	// mTLS. Fetch warden's token-verification key, then serve.
	pubKey, err := meshclient.FetchVerificationKey(ctx, cfg.WardenMeshAddr, leaf, pool, cfg.WardenSpiffe)
	if err != nil {
		slog.Error("fetch verification key", "err", err)
		os.Exit(1)
	}
	verifier := sessiontoken.NewVerifier(pubKey)

	// Per-connection audit recording is mandatory for kubernetes sessions.
	uploader, err := record.NewS3Uploader(ctx, cfg.RecordingBucket, cfg.RecordingEndpoint, cfg.RecordingRegion)
	if err != nil {
		slog.Error("recording uploader", "err", err)
		os.Exit(1)
	}
	if uploader == nil {
		slog.Error("RECORDING_S3_BUCKET is required: kubernetes sessions must be recorded")
		os.Exit(1)
	}
	ended := make(chan frontdoor.SessionEnd, 16)
	rec := frontdoor.NewRecorder(uploader, cfg.BrokerID, ended)

	fdTLS := mesh.ServerTLSConfigRole(leaf, pool, "gateway")
	fdTLS.NextProtos = []string{"http/1.1"} // gateway blind-pipes HTTP/1.1, not h2
	fdRawLn, err := net.Listen("tcp", cfg.DataplaneAddr)
	if err != nil {
		slog.Error("front door listen", "err", err)
		os.Exit(1)
	}
	fdLn := tls.NewListener(fdRawLn, fdTLS)
	fdSrv := &http.Server{
		Handler:           frontdoor.Handler(b, verifier, rec),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       rec.ConnContext,
		ConnState:         rec.ConnState,
	}
	go func() { <-ctx.Done(); _ = fdSrv.Close() }()
	go func() {
		if err := fdSrv.Serve(fdLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("front door serve", "err", err)
			os.Exit(1) // fail fast like the agent listener — a dead front door is useless
		}
	}()
	slog.Info("front door up", "addr", cfg.DataplaneAddr)

	client := meshclient.New(cfg.WardenMeshAddr, leaf, pool, cfg.WardenSpiffe)
	if err := control.Run(ctx, client, b.Registry(), cfg.BrokerID, cfg.DataplaneAddr, ended); err != nil && ctx.Err() == nil {
		slog.Error("control loop", "err", err)
		os.Exit(1)
	}
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
