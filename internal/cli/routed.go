package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newRoutedSessionsCmd(a *app) *cobra.Command {
	var customers []string
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "BGP sessions per customer name",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().RoutedSessions(ctx, ops.RoutedSessionsInput{Customers: customers}))
		}),
	}
	customerFlag(cmd, &customers)
	return cmd
}

// customerFlag is the --customer flag every fan-out command takes.
func customerFlag(cmd *cobra.Command, customers *[]string) {
	listVar(cmd.Flags(), customers, "customer", "customer name to query; repeatable or comma-separated (default: every in-use name)")
}

// analytics is the Prolexic Analytics client, over the read credentials.
func (a *app) analytics() (*analytics.Client, error) {
	c, err := a.readClient()
	if err != nil {
		return nil, err
	}
	return analytics.New(c), nil
}
