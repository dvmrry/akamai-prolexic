package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
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

// AliasesDoc lists the account's aliases, without entries.
type AliasesDoc struct {
	output.Header
	Aliases []ncfapi.AliasInfo `json:"aliases" doc:"Sorted by name, id."`
}

func (*AliasesDoc) SchemaID() string { return "prolexic.aliases.v1" }

func (d *AliasesDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tTYPE\tIP\tEDITABLE\tIN USE\tENTRIES\tACTIVE\tPROD\tRULES")
	for _, al := range d.Aliases {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%t\t%t\t%d\t%s\t%s\t%s\n", al.Name, al.ID, al.Type, al.IPVersion, al.Editable,
			al.InUse, al.EntriesCount, dash(al.ActiveVersion), dash(al.ProdVersion), dash(joinInts(al.ProdRuleIndexes)))
	}
	return tw.Flush()
}

func runAliasesList(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	editable := fs.Bool("editable", false, "only customer-editable aliases (not Akamai-managed)")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	rows, err := api.ListAliasInfo(ctx)
	if err != nil {
		return nil, err
	}
	if *editable {
		rows = slices.DeleteFunc(rows, func(r ncfapi.AliasInfo) bool { return !r.Editable })
	}
	slices.SortStableFunc(rows, func(x, y ncfapi.AliasInfo) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.ID, y.ID))
	})
	return &AliasesDoc{Aliases: nonNil(rows)}, nil
}
