//go:build unix

package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// watchResize installs a SIGWINCH handler that pushes the current terminal size
// onto resize. It returns a function that removes the handler and closes the
// channel. The most recent size is coalesced so a slow reader never blocks the
// signal handler.
func watchResize(fd int, resize chan<- [2]int) (stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sig:
				w, h, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				select {
				case resize <- [2]int{w, h}:
				default:
				}
			}
		}
	}()

	return func() {
		signal.Stop(sig)
		close(done)
		close(resize)
	}
}
