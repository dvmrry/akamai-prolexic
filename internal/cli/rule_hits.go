package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newRuleHitsListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "match statistics of every rule",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().RuleHits(ctx))
		}),
	}
}

func newRuleHitsShowCmd(a *app) *cobra.Command {
	var in ops.RuleHitInput
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one rule's statistics, and its time series with a window",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			var err error
			if in.Window, err = win.window(); err != nil {
				return nil, err
			}
			return docOf(a.ops().RuleHit(ctx, in))
		}),
	}
	cmd.Flags().StringVar(&in.Rule, "rule", "", "rule id (the ruleId from rule-hits list; required)")
	win.register(cmd, 0)
	_ = cmd.MarkFlagRequired("rule")
	return cmd
}
