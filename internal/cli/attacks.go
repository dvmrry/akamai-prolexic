package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newAttacksListCmd(a *app) *cobra.Command {
	var in ops.AttacksInput
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "list",
		Short: "attacks in a time window per customer name",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			var err error
			if in.Window, err = win.window(); err != nil {
				return nil, err
			}
			return output.Doc(a.ops().Attacks(ctx, in))
		}),
	}
	customerFlag(cmd, &in.Customers)
	win.register(cmd, ops.AttacksDefaultSince)
	return cmd
}

func newAttacksShowCmd(a *app) *cobra.Command {
	var in ops.AttackInput
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one attack's detail report",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().Attack(ctx, in))
		}),
	}
	f := cmd.Flags()
	f.Int64Var(&in.ID, "id", 0, "attack id (required)")
	f.StringVar(&in.Customer, "customer", "", "customer name the attack belongs to (required)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("customer")
	return cmd
}
