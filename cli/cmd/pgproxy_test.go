package cmd

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncBuffer is a mutex-guarded bytes.Buffer. The proxy's startup banner is
// written from the accept-loop goroutine while the test polls/reads it from
// the main goroutine; a plain bytes.Buffer isn't safe for that and trips
// -race, so tests capture output through this instead.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// echoServer accepts connections and echoes bytes back; it stands in for the
// gateway tunnel's far end.
func echoServer(t *testing.T) (dial func(context.Context, string, string) (net.Conn, error), stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	}
	return dial, func() { _ = ln.Close() }
}

func TestPostgresProxySplicesAndMintsPerConn(t *testing.T) {
	dial, stop := echoServer(t)
	defer stop()

	var mints int32
	deps := pgProxyDeps{
		mint: func(context.Context) (string, string, error) {
			atomic.AddInt32(&mints, 1)
			return "tok", "gw:443", nil
		},
		dial: dial,
	}

	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- runPostgresProxy(ctx, deps, "app", "appdb", 0, nil, &out) }()

	port := waitForPort(t, &out)

	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			t.Fatalf("dial local: %v", err)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo = %q err=%v", buf, err)
		}
		_ = c.Close()
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("proxy returned: %v", err)
	}
	if got := atomic.LoadInt32(&mints); got != 2 {
		t.Errorf("mints = %d, want 2 (one per connection)", got)
	}
	if !strings.Contains(out.String(), "sslmode=disable") || !strings.Contains(out.String(), "user=app") {
		t.Errorf("hint missing expected fields: %q", out.String())
	}
}

func waitForPort(t *testing.T, out *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if i := strings.Index(out.String(), "port="); i >= 0 {
			rest := out.String()[i+len("port="):]
			end := strings.IndexAny(rest, " \"")
			if end > 0 {
				return rest[:end]
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy did not print a port")
	return ""
}

func TestPostgresProxyExecPassthrough(t *testing.T) {
	dial, stop := echoServer(t)
	defer stop()
	deps := pgProxyDeps{
		mint: func(context.Context) (string, string, error) { return "tok", "gw", nil },
		dial: dial,
	}
	var out bytes.Buffer
	err := runPostgresProxy(context.Background(), deps, "app", "appdb", 0,
		[]string{"sh", "-c", "echo port=$PGPORT user=$PGUSER db=$PGDATABASE ssl=$PGSSLMODE"}, &out)
	if err != nil {
		t.Fatalf("exec proxy: %v", err)
	}
	s := out.String()
	// "db=appdb" and "ssl=disable" appear ONLY from the child (the hint uses
	// "dbname="/"sslmode="), so they prove the child received the PG* env.
	if !strings.Contains(s, "db=appdb") || !strings.Contains(s, "ssl=disable") || !strings.Contains(s, "user=app") {
		t.Errorf("child env not propagated: %q", s)
	}
}
