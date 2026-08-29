package pgproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
)

// TargetCredential is the minted credential for the target hop (exactly one form).
type TargetCredential struct {
	Password    string // pg-password
	X509CertPEM []byte // mtls: client leaf
	X509KeyPEM  []byte // mtls: client key
}

// DialTarget opens an authenticated connection to the Postgres target as `role`,
// injecting the credential, and returns the hijacked raw net.Conn (sitting at
// ReadyForQuery). targetServerCA (PEM, may be empty) pins the target's TLS cert
// for the mtls path.
func DialTarget(ctx context.Context, targetAddr, database, role string, cred TargetCredential, targetServerCA string) (net.Conn, error) {
	dsn := fmt.Sprintf("postgres://%s/%s?connect_timeout=10", targetAddr, database)
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse target config: %w", err)
	}
	cfg.User = role
	cfg.Fallbacks = nil // no plaintext downgrade

	switch {
	case len(cred.X509CertPEM) > 0:
		crt, err := tls.X509KeyPair(cred.X509CertPEM, cred.X509KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("client cert: %w", err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{crt}, MinVersion: tls.VersionTLS12}
		if targetServerCA != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(targetServerCA)) {
				return nil, errors.New("bad target_server_ca")
			}
			tlsCfg.RootCAs = pool
			tlsCfg.ServerName = hostOf(targetAddr) // verify-full
		} else {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // no pin configured; encryption only
		}
		cfg.TLSConfig = tlsCfg
	case cred.Password != "":
		cfg.Password = cred.Password
	default:
		return nil, errors.New("no target credential")
	}

	pgc, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect target: %w", err)
	}
	if err := pgc.SyncConn(ctx); err != nil {
		_ = pgc.Close(ctx)
		return nil, fmt.Errorf("sync target: %w", err)
	}
	hj, err := pgc.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack target: %w", err)
	}
	return hj.Conn, nil
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
