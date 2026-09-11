package cmd

import (
	"os/exec"
	"runtime"
)

// openBrowser best-effort opens url in the user's default browser. Returns an
// error if no opener is available (caller prints the URL as a fallback).
func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default: // linux, bsd, ...
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start() // #nosec G204 -- cmd is one of a fixed set of OS openers; url is not shell-interpreted
}
