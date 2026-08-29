package mesh

import (
	"io"
	"net"
	"testing"
)

func TestReadConnectReplaysTrailingBytes(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	go func() {
		_, _ = io.WriteString(client, "CONNECT db.prod HTTP/1.1\r\n"+
			"Host: db.prod\r\n"+
			"Authorization: Bearer tok123\r\n"+
			"\r\n"+
			"PGDATA")
	}()

	token, tunnel, err := ReadConnect(server)
	if err != nil {
		t.Fatalf("ReadConnect: %v", err)
	}
	if token != "tok123" {
		t.Fatalf("token = %q, want tok123", token)
	}

	buf := make([]byte, len("PGDATA"))
	if _, err := io.ReadFull(tunnel, buf); err != nil {
		t.Fatalf("read trailing bytes: %v", err)
	}
	if string(buf) != "PGDATA" {
		t.Fatalf("trailing = %q, want PGDATA", buf)
	}
}

func TestReadConnectRejectsMissingAuth(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		_, _ = io.WriteString(client, "CONNECT db.prod HTTP/1.1\r\nHost: db.prod\r\n\r\n")
	}()
	if _, _, err := ReadConnect(server); err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestReadConnectRejectsEmptyBearer(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		_, _ = io.WriteString(client, "CONNECT db.prod HTTP/1.1\r\nAuthorization: Bearer \r\n\r\n")
	}()
	if _, _, err := ReadConnect(server); err == nil {
		t.Fatal("expected error for empty bearer token")
	}
}

func TestWriteEstablished(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	go func() {
		_ = WriteEstablished(client)
		_ = client.Close()
	}()

	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	want := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if string(got) != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}
