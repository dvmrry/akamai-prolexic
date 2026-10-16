package cli

import (
	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/mcpfront"
)

func newMCPCmd(a *app) *cobra.Command {
	var root string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "offer the read-only operations as MCP tools to a local agent, over stdio",
		Long: "Speaks the Model Context Protocol on stdin and stdout, for an agent's MCP client that starts prolexic as a child process. " +
			"No network listener. The tools read live state with the read credentials and edit the local desired file; there is no apply: " +
			"changes reach the firewall through a reviewed pull request and CI. File paths are confined to --root.",
		Example: `  claude mcp add prolexic -- prolexic mcp --root /path/to/desired-state-repo`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.ran = true
			rt := a.ops()
			rt.WriteClient = nil // read-only, whatever credentials are configured
			return mcpfront.RunStdio(cmd.Context(), mcpfront.Options{Runtime: rt, Root: root})
		},
	}
	cmd.Flags().StringVar(&root, "root", "", "directory file paths are resolved against and confined to (default: the working directory)")
	return cmd
}
