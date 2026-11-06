package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newTargetsListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "every target of the account",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().Targets(ctx))
		}),
	}
}

func newTargetsShowCmd(a *app) *cobra.Command {
	var in ops.TargetInput
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one target by id",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().Target(ctx, in))
		}),
	}
	cmd.Flags().StringVar(&in.ID, "id", "", "target id (required)")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
