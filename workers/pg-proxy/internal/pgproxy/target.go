package pgproxy

import (
	"context"
	"crypto/tls"
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
// ReadyForQuery). verifiedTLS is the identity-pinned TLS config the handler built
// from the anchor it already matched on the credential-free observe; it MUST be
// non-nil, so this credentialed handshake re-authenticates the identical approved
// target identity. There is NO unverified-TLS path — a session never reaches here
// without a matched anchor.
func DialTarget(ctx context.Context, targetAddr, database, role string, cred TargetCredential, verifiedTLS *tls.Config) (net.Conn, error) {
	if verifiedTLS == nil {
		return nil, errors.New("refusing to dial target without a verified TLS identity config")
	}
	dsn := fmt.Sprintf("postgres://%s/%s?connect_timeout=10", targetAddr, database)
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse target config: %w", err)
	}
	cfg.User = role
	cfg.Fallbacks = nil // no plaintext downgrade

	tlsCfg := verifiedTLS.Clone()
	switch {
	case len(cred.X509CertPEM) > 0:
		crt, err := tls.X509KeyPair(cred.X509CertPEM, cred.X509KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{crt}
	case cred.Password != "":
		cfg.Password = cred.Password
	default:
		return nil, errors.New("no target credential")
	}
	cfg.TLSConfig = tlsCfg

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

// HostOf returns the host portion of a "host:port" address (or the address
// unchanged if it carries no port).
func HostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// SplitTargetAddr splits a "host:port" target address into host and a validated
// uint32 port, for the credential-free observe.
func SplitTargetAddr(addr string) (string, uint32, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("split target address %q: %w", addr, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target port in %q", addr)
	}
	return host, uint32(port), nil
}
