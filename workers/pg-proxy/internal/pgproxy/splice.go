package pgproxy

import (
	"io"
	"net"
)

// Splice copies bytes between client and target until either side closes or
// cancel is fired, then closes both conns.
func Splice(client, target net.Conn, cancel <-chan struct{}) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	select {
	case <-done:
	case <-cancel:
	}
	_ = client.Close()
	_ = target.Close()
}
