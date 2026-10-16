package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newVerifyCmd(a *app) *cobra.Command {
	var in ops.VerifyInput
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "check a saved plan's expected end state against a fresh read (read-only)",
		Long: "Reads every alias in a saved plan (prolexic plan's JSON) fresh and checks the plan's expected end state: " +
			"each added entry is live, each removed entry is gone, the entry count is the plan's unchanged plus added (nothing extra), " +
			"and production carries the active version. Run it after apply, against the plan that was reviewed. " +
			"Exits 7 when anything doesn't match.",
		Example: "  prolexic plan --file desired.json --out plan.json\n  prolexic apply --file desired.json --plan plan.json\n  prolexic verify --plan plan.json",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().Verify(ctx, in))
		}),
	}
	cmd.Flags().StringVar(&in.Plan, "plan", "", "the saved plan document (JSON from prolexic plan)")
	return cmd
}
