package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/trevex/jumpgate/cli/internal/config"
	"github.com/trevex/jumpgate/cli/internal/output"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI contexts",
}

var configGetContextsCmd = &cobra.Command{
	Use:   "get-contexts",
	Short: "List configured contexts",
	Args:  cobra.NoArgs,
	RunE:  runConfigGetContexts,
}

var configCurrentContextCmd = &cobra.Command{
	Use:   "current-context",
	Short: "Print the current context",
	Args:  cobra.NoArgs,
	RunE:  runConfigCurrentContext,
}

var configUseContextCmd = &cobra.Command{
	Use:   "use-context <name>",
	Short: "Switch the current context",
	Args:  cobra.ExactArgs(1),
	RunE:  runConfigUseContext,
}

func init() {
	configCmd.AddCommand(configGetContextsCmd)
	configCmd.AddCommand(configCurrentContextCmd)
	configCmd.AddCommand(configUseContextCmd)
	rootCmd.AddCommand(configCmd)
}

// contextRow is the JSON shape emitted per context by get-contexts.
type contextRow struct {
	Name       string `json:"name"`
	WardenAddr string `json:"warden_addr"`
	Current    bool   `json:"current"`
}

func runConfigGetContexts(cmd *cobra.Command, _ []string) error {
	f, err := config.LoadFile()
	if err != nil {
		return err
	}

	names := make([]string, 0, len(f.Contexts))
	for name := range f.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([][]string, 0, len(names))
	items := make([]contextRow, 0, len(names))
	for _, name := range names {
		ctx := f.Contexts[name]
		current := name == f.CurrentContext
		marker := ""
		if current {
			marker = "*"
		}
		rows = append(rows, []string{marker, name, ctx.WardenAddr})
		items = append(items, contextRow{
			Name:       name,
			WardenAddr: ctx.WardenAddr,
			Current:    current,
		})
	}

	return output.Render(cmd.OutOrStdout(), flagOutput, items, &output.Table{
		Headers: []string{"CURRENT", "NAME", "WARDEN_ADDR"},
		Rows:    rows,
	})
}

func runConfigCurrentContext(cmd *cobra.Command, _ []string) error {
	f, err := config.LoadFile()
	if err != nil {
		return err
	}
	if f.CurrentContext == "" {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no current context set")
		return nil
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), f.CurrentContext)
	return nil
}

func runConfigUseContext(cmd *cobra.Command, args []string) error {
	if err := config.UseContext(args[0]); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "switched to context %q\n", args[0])
	return nil
}
