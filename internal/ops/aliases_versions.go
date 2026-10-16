package ops

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

// AliasVersionsInput names one alias.
type AliasVersionsInput struct {
	Name string // the alias name; give exactly one of Name and ID
	ID   int64  // the alias id
}

// AliasVersions is one alias's version history.
func (r *Runtime) AliasVersions(ctx context.Context, in AliasVersionsInput) (*AliasVersionsDoc, error) {
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	al, err := resolveAlias(ctx, api, in.Name, in.ID)
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
