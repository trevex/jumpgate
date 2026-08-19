//go:build !unix

package cmd

// watchResize is a no-op on platforms without SIGWINCH: the resize channel is
// closed immediately so the client simply keeps its initial window size.
func watchResize(_ int, resize chan<- [2]int) (stop func()) {
	close(resize)
	return func() {}
}
