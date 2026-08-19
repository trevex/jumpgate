// Package cmd defines the jumpgate CLI command tree.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/jumpgate/cli/internal/config"
)

var (
	flagWardenAddr string
	flagCAFile     string
	flagToken      string
	flagContext    string
	flagOutput     string
)

// rootCmd is the base jumpgate command.
var rootCmd = &cobra.Command{
	Use:           "jumpgate",
	Short:         "jumpgate CLI",
	Long:          "jumpgate is the command-line client for the jumpgate access platform.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagWardenAddr, "warden-addr", "", "warden base URL (e.g. http://localhost:8080)")
	pf.StringVar(&flagCAFile, "ca", "", "path to a CA certificate for verifying warden's TLS")
	pf.StringVar(&flagToken, "token", "", "bearer token (overrides the current context)")
	pf.StringVar(&flagContext, "context", "", "config context to use (defaults to the current context)")
	pf.StringVarP(&flagOutput, "output", "o", "table", "output format: table | json")
	rootCmd.AddCommand(loginCmd)
}

// Execute runs the root command. It returns any error to the caller so main can
// choose the exit code.
func Execute() error {
	return rootCmd.Execute()
}

// resolveContext returns the effective context for a command (flag > env > file).
func resolveContext() (config.Context, error) {
	return config.Resolve(flagContext, config.Overrides{WardenAddr: flagWardenAddr, CAFile: flagCAFile, Token: flagToken})
}
