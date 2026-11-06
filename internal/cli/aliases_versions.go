package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newAliasesVersionsCmd(a *app) *cobra.Command {
	var in ops.AliasVersionsInput
	cmd := &cobra.Command{
		Use:   "versions",
		Short: "one alias's version history",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			if err := requireOneAlias(in.Name, in.ID); err != nil {
				return nil, err
			}
			return output.Doc(a.ops().AliasVersions(ctx, in))
		}),
	}
	aliasSelector(cmd, &in.Name, &in.ID)
	return cmd
}
