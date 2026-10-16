package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newRoutedRoutesCmd(a *app) *cobra.Command {
	var in ops.RoutedRoutesInput
	cmd := &cobra.Command{
		Use:   "routes",
		Short: "routes announced to Akamai per customer name",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().RoutedRoutes(ctx, in))
		}),
	}
	customerFlag(cmd, &in.Customers)
	cmd.Flags().StringVar(&in.Prefix, "prefix", "", "only routes for exactly this prefix (a bare address means /32 or /128)")
	return cmd
}
