// Package sshclient runs an interactive SSH client over an already-established
// tunnel to the worker, wiring the remote session to the local process stdio.
package sshclient

import (
	"context"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

// exitMissing is the code reported when the remote peer closes the channel
// without sending an exit status.
const exitMissing = 255

// PTY describes the pseudo-terminal to request for an interactive session.
// Resize, when non-nil, delivers new {width, height} pairs that are forwarded
// to the remote as window-change requests until the channel is closed.
type PTY struct {
	Term   string
	W, H   int
	Resize <-chan [2]int
}

// Run performs the SSH client handshake over tunnel and runs an interactive
// session wired to the supplied stdio, returning the remote exit code.
//
// When pty is non-nil a pseudo-terminal is requested and window-resize events
// from pty.Resize are forwarded to the remote; otherwise the session is
// non-interactive.
//
// The host-key check is intentionally a no-op: the tunnel is already mutually
// authenticated to the worker (client->gateway TLS, gateway->worker mTLS with a
// pinned worker identity), so verifying the SSH host key would only
// re-authenticate an already-authenticated channel.
func Run(ctx context.Context, tunnel net.Conn, login string, signer ssh.Signer, in io.Reader, out, errw io.Writer, pty *PTY) (int, error) {
	cfg := &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // tunnel is already mutually authenticated to the worker
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(tunnel, "jumpgate", cfg)
	if err != nil {
		return 0, err
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer func() { _ = session.Close() }()

	session.Stdin = in
	session.Stdout = out
	session.Stderr = errw

	if pty != nil {
		term := pty.Term
		if term == "" {
			term = "xterm-256color"
		}
		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty(term, pty.H, pty.W, modes); err != nil {
			return 0, err
		}
		if pty.Resize != nil {
			go forwardResizes(ctx, session, pty.Resize)
		}
	}

	if err := session.Shell(); err != nil {
		return 0, err
	}

	return waitExit(session.Wait())
}

// forwardResizes relays window-size changes to the remote session until the
// resize channel is closed or the context is cancelled.
func forwardResizes(ctx context.Context, session *ssh.Session, resize <-chan [2]int) {
	for {
		select {
		case <-ctx.Done():
			return
		case size, ok := <-resize:
			if !ok {
				return
			}
			_ = session.WindowChange(size[1], size[0])
		}
	}
}

// waitExit maps the result of session.Wait to a remote exit code. A clean exit
// is 0, a non-zero exit is taken from the ExitError, a missing exit status maps
// to a sentinel, and any other error is returned to the caller.
func waitExit(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	var missingErr *ssh.ExitMissingError
	if errors.As(err, &missingErr) {
		return exitMissing, nil
	}
	return 0, err
}
