package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newCustomersCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "customers",
		Short: "the account's customer names",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().Customers(ctx))
		}),
	}
}
