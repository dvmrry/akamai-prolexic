package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newManagedACLCmd(a *app) *cobra.Command {
	var in ops.ManagedACLInput
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "a policy domain's latest managed-services ACL version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().ManagedACL(ctx, in))
		}),
	}
	cmd.Flags().StringVar(&in.PolicyDomain, "policy-domain", "", "policy domain (required)")
	_ = cmd.MarkFlagRequired("policy-domain")
	return cmd
}

func newManagedRuleHitsCmd(a *app) *cobra.Command {
	var in ops.ManagedRuleHitsInput
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "rule-hits",
		Short: "a policy domain's rule statistics, and one rule's time series",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			var err error
			if in.Window, err = win.window(); err != nil {
				return nil, err
			}
			return docOf(a.ops().ManagedRuleHits(ctx, in))
		}),
	}
	f := cmd.Flags()
	f.StringVar(&in.PolicyDomain, "policy-domain", "", "policy domain (required)")
	f.StringVar(&in.Rule, "rule", "", "one rule's id (its uuid): show that rule and its time series")
	win.register(cmd, 0)
	_ = cmd.MarkFlagRequired("policy-domain")
	return cmd
}
