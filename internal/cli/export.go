package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newExportCmd(a *app) *cobra.Command {
	var in ops.ExportInput
	var role string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "write live editable aliases to the desired file (bootstrap, or adopt drift)",
		Long:  "Reads live state (read credentials only) and writes the editable aliases to the desired file in canonical form. A missing or empty file is bootstrapped from every editable alias; an existing file is updated to the live entries of the aliases it names, keeping their metadata.",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			in.Role = ncf.Role(role)
			if in.Role != ncf.RoleDeny && in.Role != ncf.RoleAllow { // the fallback for aliases no rule uses
				return nil, apperr.New(apperr.Usage, "--role must be deny or allow, not %q", role)
			}
			return docOf(a.ops().Export(ctx, in))
		}),
	}
	fileFlag(cmd, &in.File)
	cmd.Flags().BoolVar(&in.All, "all", false, "also add editable live aliases the file doesn't name")
	cmd.Flags().StringVar(&role, "role", string(ncf.RoleDeny), "role for aliases no deployed rule references (deployed rules decide the rest): deny or allow")
	return cmd
}
