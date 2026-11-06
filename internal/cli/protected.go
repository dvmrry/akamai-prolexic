package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newProtectedCmd(a *app) *cobra.Command {
	var in ops.ProtectedInput
	cmd := &cobra.Command{
		Use:   "protected",
		Short: "prefixes and AS numbers treated as own space, per customer name",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().Protected(ctx, in))
		}),
	}
	listVar(cmd.Flags(), &in.Customers, "customer", "customer name to query; repeatable or comma-separated (default: every name, in use or not)")
	return cmd
}
