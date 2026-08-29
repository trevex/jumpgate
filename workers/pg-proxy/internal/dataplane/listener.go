package dataplane

import (
	"context"
	"crypto/tls"
	"log/slog"

	"github.com/trevex/jumpgate/warden/gen/jumpgate/dataplane/v1/dataplanev1connect"
	"github.com/trevex/jumpgate/workers/pg-proxy/internal/control"
)

// Serve accepts mesh mTLS connections on addr (pinning the gateway SPIFFE via
// tlsCfg) and dispatches each to handleConn until ctx is cancelled.
func Serve(ctx context.Context, addr string, tlsCfg *tls.Config, workerID string, client dataplanev1connect.DataplaneServiceClient, reg *control.Registry, ended chan<- control.SessionEnd) error {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("accept", "err", err)
			continue
		}
		go handleConn(ctx, conn, workerID, client, reg, ended)
	}
}
