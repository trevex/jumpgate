package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// LoadKeyPair reads the worker's mesh leaf cert+key and the CA bundle from disk.
func LoadKeyPair(certFile, keyFile, caFile string) (tls.Certificate, *x509.CertPool, error) {
	crt, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load mesh keypair: %w", err)
	}
	caPEM, err := os.ReadFile(caFile) //nolint:gosec // path from trusted env config
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read mesh CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, errors.New("no certs in mesh CA bundle")
	}
	return crt, pool, nil
}

// verifyChainAndSpiffe verifies the leaf chains to pool and carries exactly one
// URI SAN equal to expectSpiffe. Fail closed.
func verifyChainAndSpiffe(certs []*x509.Certificate, pool *x509.CertPool, expectSpiffe string, eku x509.ExtKeyUsage) error {
	if len(certs) == 0 {
		return errors.New("peer presented no certificate")
	}
	opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool(), KeyUsages: []x509.ExtKeyUsage{eku}}
	for _, inter := range certs[1:] {
		opts.Intermediates.AddCert(inter)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("mesh chain verify: %w", err)
	}
	uris := certs[0].URIs
	if len(uris) != 1 || uris[0].String() != expectSpiffe {
		return fmt.Errorf("peer SPIFFE mismatch: got %v, want %q", uris, expectSpiffe)
	}
	return nil
}

// ClientTLSConfig builds the worker's outbound mesh client config: presents the
// worker leaf, verifies the server chain, and pins the server SPIFFE. h2 for connect-go.
func ClientTLSConfig(leaf tls.Certificate, pool *x509.CertPool, expectServerSpiffe string) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{leaf},
		RootCAs:            pool,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // chain+SPIFFE pinned in VerifyConnection; URI-SAN certs carry no DNS name
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyChainAndSpiffe(cs.PeerCertificates, pool, expectServerSpiffe, x509.ExtKeyUsageServerAuth)
		},
	}
}

// ServerTLSConfig builds the worker's inbound (gateway-facing) config: presents
// the worker leaf, requires+verifies the client cert chain, and pins the gateway
// SPIFFE. (Used by the data-plane listener in a later plan.)
func ServerTLSConfig(leaf tls.Certificate, pool *x509.CertPool, expectClientSpiffe string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		// Disable resumption so VerifyPeerCertificate runs on every handshake;
		// resumed sessions would otherwise skip the SPIFFE pin (gosec G123).
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			return verifyChainAndSpiffe(certs, pool, expectClientSpiffe, x509.ExtKeyUsageClientAuth)
		},
	}
}
