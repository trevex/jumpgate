package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startStubServer stands up an SSH server on a loopback listener. It accepts
// any public key, and on a session's shell request echoes stdin back to stdout
// until EOF, then sends exitCode as the exit status. It returns the client-side
// connection dialed to that server.
func startStubServer(t *testing.T, exitCode uint32) net.Conn {
	t.Helper()

	hostKey := generateSigner(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		serverSide, err := ln.Accept()
		if err != nil {
			return
		}
		serveConn(serverSide, cfg, exitCode)
	}()

	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return clientSide
}

func serveConn(conn net.Conn, cfg *ssh.ServerConfig, exitCode uint32) {
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = serverConn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go handleSession(ch, chReqs, exitCode)
	}
}

func handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, exitCode uint32) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Echo stdin to stdout until the client closes its write side.
			_, _ = io.Copy(ch, ch)
			status := struct{ Status uint32 }{exitCode}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
			_ = ch.Close()
			return
		case "pty-req", "env", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}
	return signer
}

func runAgainstStub(t *testing.T, exitCode uint32) (string, int, error) {
	t.Helper()

	tunnel := startStubServer(t, exitCode)
	signer := generateSigner(t)

	const line = "hello over the tunnel\n"
	var out bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	var code int
	var runErr error
	go func() {
		code, runErr = Run(ctx, tunnel, "tester", signer, strings.NewReader(line), &out, io.Discard, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Run did not return before timeout")
	}
	return out.String(), code, runErr
}

func TestRunEchoesAndExitsZero(t *testing.T) {
	out, code, err := runAgainstStub(t, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "hello over the tunnel") {
		t.Fatalf("stdout = %q, want echoed line", out)
	}
}

func TestRunMapsNonZeroExit(t *testing.T) {
	out, code, err := runAgainstStub(t, 3)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(out, "hello over the tunnel") {
		t.Fatalf("stdout = %q, want echoed line", out)
	}
}
