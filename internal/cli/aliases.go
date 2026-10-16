package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ncfV2 is the concrete NCF v2 client over the read credentials, for the
// read-only commands that go beyond ncf.Store.
func (a *app) ncfV2() (*ncfapi.V2, error) {
	c, err := a.readClient()
	if err != nil {
		return nil, err
	}
	return ncfapi.NewV2(c), nil
}

func newAliasesListCmd(a *app) *cobra.Command {
	var in ops.AliasesInput
	cmd := &cobra.Command{
		Use:   "list",
		Short: "every alias, without entries",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return docOf(a.ops().Aliases(ctx, in))
		}),
	}
	cmd.Flags().BoolVar(&in.EditableOnly, "editable", false, "only customer-editable aliases (not Akamai-managed)")
	return cmd
}

func newAliasesShowCmd(a *app) *cobra.Command {
	var in ops.AliasInput
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one alias's entries at a version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			if err := requireOneAlias(in.Name, in.ID); err != nil {
				return nil, err
			}
			return docOf(a.ops().Alias(ctx, in))
		}),
	}
	aliasSelector(cmd, &in.Name, &in.ID)
	cmd.Flags().StringVar(&in.Version, "version", "", "version id, e.g. V3 (default: the alias's active version)")
	return cmd
}

// aliasSelector is the --name/--id pair that picks one alias.
func aliasSelector(cmd *cobra.Command, name *string, id *int64) {
	cmd.Flags().StringVar(name, "name", "", "alias name")
	cmd.Flags().Int64Var(id, "id", 0, "alias id")
}

// requireOneAlias is the front check that names the flags.
func requireOneAlias(name string, id int64) error {
	if (name == "") == (id == 0) {
		return apperr.New(apperr.Usage, "give exactly one of --name and --id")
	}
	return nil
}
