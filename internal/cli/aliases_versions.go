package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// AliasVersionsDoc is one alias's full version history.
type AliasVersionsDoc struct {
	output.Header
	Alias    ncfapi.AliasInfo     `json:"alias"`
	Versions []ncfapi.VersionInfo `json:"versions" doc:"Newest first (by version number)."`
}

func (*AliasVersionsDoc) SchemaID() string { return "prolexic.alias-versions.v1" }

func (d *AliasVersionsDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tACTIVE\tPROD\tENTRIES\tSOURCE\tUPDATED\tBY\tCOMMENT")
	for _, v := range d.Versions {
		active, prod := "", ""
		if v.Active {
			active = "active"
		}
		if v.Version == d.Alias.ProdVersion {
			prod = "prod"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", v.Version, dash(active), dash(prod), v.EntriesCount,
			dash(v.SourceVersion), dash(v.Updated), dash(v.UpdatedBy), dash(v.Comment))
	}
	return tw.Flush()
}

// versionNumber reads "V12" as 12; ids that aren't of that form sort as 0.
func versionNumber(v string) int {
	n, _ := strconv.Atoi(strings.TrimLeft(v, "Vv"))
	return n
}

func runAliasesVersions(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	name := fs.String("name", "", "alias name")
	id := fs.Int64("id", 0, "alias id")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	al, err := resolveAlias(ctx, api, *name, *id)
	if err != nil {
		return nil, err
	}
	rows, err := api.VersionHistory(ctx, al.ID)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y ncfapi.VersionInfo) int {
		return cmp.Or(cmp.Compare(versionNumber(y.Version), versionNumber(x.Version)), cmp.Compare(y.Version, x.Version))
	})
	return &AliasVersionsDoc{Alias: al, Versions: nonNil(rows)}, nil
}
