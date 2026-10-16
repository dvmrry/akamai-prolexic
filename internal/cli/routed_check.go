package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newRoutedCheckCmd(a *app) *cobra.Command {
	var in ops.RoutedCheckInput
	cmd := &cobra.Command{
		Use:     "check",
		Short:   "check a prefix has propagated (or gone) on every session",
		Long:    "Checks, per BGP session, that the prefix is announced to Akamai (--expect present) or not (--expect absent). With --wait it keeps polling every --interval until satisfied or the time runs out.",
		Example: "  prolexic routed check --prefix 198.51.100.0/24 --wait 10m",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			if in.Interval <= 0 {
				return nil, apperr.New(apperr.Usage, "--interval must be positive")
			}
			return docOf(a.ops().RoutedCheck(ctx, in))
		}),
	}
	customerFlag(cmd, &in.Customers)
	f := cmd.Flags()
	listVar(f, &in.Sites, "site", "only sessions in this data center; repeatable or comma-separated")
	f.StringVar(&in.Prefix, "prefix", "", "the prefix to check (required; a bare address means /32 or /128)")
	f.StringVar(&in.Expect, "expect", "present", "present: every expected session carries the prefix; absent: none does")
	f.DurationVar(&in.Wait, "wait", 0, "keep checking until satisfied or this long has passed (0: check once)")
	f.DurationVar(&in.Interval, "interval", ops.DefaultCheckInterval, "time between checks while waiting")
	_ = cmd.MarkFlagRequired("prefix")
	return cmd
}
