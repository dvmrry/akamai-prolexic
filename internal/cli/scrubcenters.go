package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newScrubCentersCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "scrub-centers",
		Short: "active scrub centers",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().ScrubCenters(ctx))
		}),
	}
}
