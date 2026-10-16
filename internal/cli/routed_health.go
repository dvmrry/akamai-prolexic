package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newRoutedHealthCmd(a *app) *cobra.Command {
	var in ops.RoutedHealthInput
	cmd := &cobra.Command{
		Use:   "health",
		Short: "healthy and total tunnels per location and router",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().RoutedHealth(ctx, in))
		}),
	}
	customerFlag(cmd, &in.Customers)
	return cmd
}
