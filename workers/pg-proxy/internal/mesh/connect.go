package mesh

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

const maxConnectHeader = 8 << 10

// ReadConnect reads a CONNECT preamble from conn, returns the bearer token and a
// net.Conn that replays any bytes buffered past the header terminator. It does
// NOT write a response (the caller decides success/failure).
func ReadConnect(conn net.Conn) (token string, tunnel net.Conn, err error) {
	br := bufio.NewReaderSize(conn, maxConnectHeader)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("read CONNECT line: %w", err)
	}
	fields := strings.Fields(reqLine)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		return "", nil, fmt.Errorf("not a CONNECT request: %q", strings.TrimSpace(reqLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", nil, fmt.Errorf("read CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		name, val, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "authorization") {
			if rest, ok := cutBearer(strings.TrimSpace(val)); ok {
				token = rest
			}
		}
	}
	if token == "" {
		return "", nil, fmt.Errorf("CONNECT missing bearer token")
	}
	if br.Buffered() > 0 {
		buf := make([]byte, br.Buffered())
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", nil, err
		}
		return token, &bufConn{r: io.MultiReader(strings.NewReader(string(buf)), conn), Conn: conn}, nil
	}
	return token, conn, nil
}

func cutBearer(v string) (string, bool) {
	if len(v) >= 7 && strings.EqualFold(v[:7], "Bearer ") {
		return strings.TrimSpace(v[7:]), true
	}
	return "", false
}

// WriteEstablished writes the CONNECT success response.
func WriteEstablished(conn net.Conn) error {
	_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	return err
}

// WriteStatus writes an HTTP error status line (e.g. 403) before the caller closes.
func WriteStatus(conn net.Conn, code int, reason string) {
	_, _ = io.WriteString(conn, fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", code, reason))
}

type bufConn struct {
	r io.Reader
	net.Conn
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }
