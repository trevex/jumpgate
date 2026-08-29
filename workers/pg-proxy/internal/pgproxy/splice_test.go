package pgproxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestSpliceEchoes(t *testing.T) {
	clientLocal, clientRemote := net.Pipe()
	targetLocal, targetRemote := net.Pipe()

	cancel := make(chan struct{})
	go Splice(clientRemote, targetRemote, cancel)

	// Echo server on the target side: read whatever the splice forwards and
	// write it straight back.
	go func() {
		buf := make([]byte, 64)
		n, err := targetLocal.Read(buf)
		if err != nil {
			return
		}
		_, _ = targetLocal.Write(buf[:n])
	}()

	deadline := time.Now().Add(2 * time.Second)
	_ = clientLocal.SetDeadline(deadline)

	if _, err := clientLocal.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}

	got := make([]byte, 4)
	if _, err := io.ReadFull(clientLocal, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, []byte("ping")) {
		t.Fatalf("got %q, want %q", got, "ping")
	}
}

func TestSpliceCancelCloses(t *testing.T) {
	clientLocal, clientRemote := net.Pipe()
	_, targetRemote := net.Pipe()

	cancel := make(chan struct{})
	go Splice(clientRemote, targetRemote, cancel)

	close(cancel)

	_ = clientLocal.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := clientLocal.Read(buf); err == nil {
		t.Fatal("expected read error after cancel closed the conn, got nil")
	}
}
