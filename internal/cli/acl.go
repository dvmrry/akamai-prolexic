package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newACLVersionsCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "versions",
		Short: "every ACL version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().ACLVersions(ctx))
		}),
	}
}

func newACLShowCmd(a *app) *cobra.Command {
	var in ops.ACLShowInput
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one ACL version's rules (default: production)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().ACLShow(ctx, in))
		}),
	}
	cmd.Flags().IntVar(&in.Version, "version", 0, "ACL version number (default: the version in production)")
	return cmd
}

func newACLDeploymentCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "deployment",
		Short: "deployment-status rulesets and which is in production",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().ACLDeployment(ctx))
		}),
	}
}
