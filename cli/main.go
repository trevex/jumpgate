// Command jumpgate is the command-line client for the jumpgate access platform.
package main

import (
	"fmt"
	"os"

	"github.com/trevex/jumpgate/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
