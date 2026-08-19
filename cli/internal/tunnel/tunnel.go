// Package tunnel establishes a raw connection to the gateway by TLS-dialing it
// and performing an HTTP CONNECT with the session token.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Dial establishes a TLS connection to the gateway and performs an HTTP CONNECT
// for assetID authenticated with token. On a 200 response it returns the raw
// tunnel connection.
//
// The gateway's leaf certificate carries only a URI SAN (no DNS name), so the
// standard TLS hostname check would fail. We disable it and verify the chain
// ourselves against the CA bundle in caFile, ignoring the hostname.
func Dial(ctx context.Context, gatewayEndpoint, caFile, assetID, token string) (net.Conn, error) {
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		RootCAs: pool,
		// The gateway leaf has only a URI SAN, so Go's hostname verification
		// against the dial address fails. Bypass it and verify the presented
		// chain against our CA pool manually, without a hostname check.
		InsecureSkipVerify: true, //nolint:gosec // chain verified in VerifyConnection; hostname check intentionally skipped for URI-SAN gateway certs
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("gateway presented no certificate")
			}
			opts := x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool()}
			for _, inter := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(inter)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}

	dialer := &tls.Dialer{Config: cfg}
	rawConn, err := dialer.DialContext(ctx, "tcp", gatewayEndpoint)
	if err != nil {
		return nil, fmt.Errorf("dialing gateway: %w", err)
	}
	conn := rawConn.(*tls.Conn)

	if err := writeConnect(conn, gatewayEndpoint, assetID, token); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	if err := readConnectStatus(br); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Any bytes the bufio.Reader buffered past the header terminator belong to
	// the tunnel; wrap the conn so those are read before the socket.
	if br.Buffered() > 0 {
		return &bufConn{r: io.MultiReader(bufReaderBytes(br), conn), Conn: conn}, nil
	}
	return conn, nil
}

// writeConnect sends the CONNECT request line and headers.
func writeConnect(conn net.Conn, endpoint, assetID, token string) error {
	req := "CONNECT " + assetID + " HTTP/1.1\r\n" +
		"Host: " + endpoint + "\r\n" +
		"Authorization: Bearer " + token + "\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("writing CONNECT: %w", err)
	}
	return nil
}

// readConnectStatus reads the response up to the header terminator and requires
// a 200 status code.
func readConnectStatus(br *bufio.Reader) error {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading CONNECT response: %w", err)
	}
	code, err := parseStatusCode(statusLine)
	if err != nil {
		return err
	}

	// Drain the remaining header lines up to the blank line terminator.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if code != 200 {
		return fmt.Errorf("gateway refused CONNECT: status %d", code)
	}
	return nil
}

// parseStatusCode extracts the numeric status code from an HTTP status line such
// as "HTTP/1.1 200 Connection Established".
func parseStatusCode(line string) (int, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, fmt.Errorf("malformed CONNECT status line: %q", strings.TrimSpace(line))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("malformed CONNECT status code: %q", fields[1])
	}
	return code, nil
}

// bufReaderBytes returns the bytes currently buffered in br as a reader.
func bufReaderBytes(br *bufio.Reader) io.Reader {
	buf := make([]byte, br.Buffered())
	_, _ = io.ReadFull(br, buf)
	return strings.NewReader(string(buf))
}

// bufConn is a net.Conn whose Read prefers a reader holding tunnel bytes that
// were already buffered while parsing the CONNECT response, then falls through
// to the underlying connection.
type bufConn struct {
	r io.Reader
	net.Conn
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// loadCAPool reads a PEM CA bundle from caFile into a cert pool.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, errors.New("no CA file configured for the gateway")
	}
	pem, err := os.ReadFile(caFile) // #nosec G304 -- caFile comes from CLI config, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("reading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	return pool, nil
}
