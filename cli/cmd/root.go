// Package cmd defines the jumpgate CLI command tree.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/trevex/jumpgate/cli/internal/config"
)

// flagCfg holds config values supplied via persistent flags. Empty fields mean
// "unset" so they do not override env or file values during Overlay.
var flagCfg config.Config

// rootCmd is the base jumpgate command.
var rootCmd = &cobra.Command{
	Use:           "jumpgate",
	Short:         "jumpgate CLI",
	Long:          "jumpgate is the command-line client for the jumpgate access platform.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagCfg.WardenAddr, "warden-addr", "", "warden base URL (e.g. http://localhost:8080)")
	rootCmd.PersistentFlags().StringVar(&flagCfg.CAFile, "ca", "", "path to a CA certificate for verifying warden's TLS")

	rootCmd.AddCommand(loginCmd)
}

// Execute runs the root command. It returns any error to the caller so main can
// choose the exit code.
func Execute() error {
	return rootCmd.Execute()
}

// effectiveConfig resolves the persisted config layered with env and flags.
// Precedence is flag > env > file.
func effectiveConfig() (config.Config, error) {
	c, err := config.Load()
	if err != nil {
		return config.Config{}, err
	}
	return c.Overlay(flagCfg), nil
}
