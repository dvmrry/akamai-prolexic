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

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
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

func newAliasesListCmd(a *app) *cobra.Command {
	var editable bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "every alias, without entries",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return aliasesList(ctx, a, editable)
		}),
	}
	cmd.Flags().BoolVar(&editable, "editable", false, "only customer-editable aliases (not Akamai-managed)")
	return cmd
}

func aliasesList(ctx context.Context, a *app, editable bool) (output.Document, error) {
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	rows, err := api.ListAliasInfo(ctx)
	if err != nil {
		return nil, err
	}
	if editable {
		rows = slices.DeleteFunc(rows, func(r ncfapi.AliasInfo) bool { return !r.Editable })
	}
	slices.SortStableFunc(rows, func(x, y ncfapi.AliasInfo) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.ID, y.ID))
	})
	return &AliasesDoc{Aliases: nonNil(rows)}, nil
}

// resolveAlias finds the one alias named by --name or --id.
func resolveAlias(ctx context.Context, api *ncfapi.V2, name string, id int64) (ncfapi.AliasInfo, error) {
	if (name == "") == (id == 0) {
		return ncfapi.AliasInfo{}, apperr.New(apperr.Usage, "give exactly one of --name and --id")
	}
	all, err := api.ListAliasInfo(ctx)
	if err != nil {
		return ncfapi.AliasInfo{}, err
	}
	var hits []ncfapi.AliasInfo
	for _, al := range all {
		if (name != "" && al.Name == name) || (id != 0 && al.ID == id) {
			hits = append(hits, al)
		}
	}
	switch len(hits) {
	case 0:
		return ncfapi.AliasInfo{}, apperr.New(apperr.NotFound, "no alias %s", cmp.Or(name, strconv.FormatInt(id, 10)))
	case 1:
		return hits[0], nil
	}
	return ncfapi.AliasInfo{}, apperr.New(apperr.Upstream, "alias name %q is ambiguous: %d aliases carry it; use --id", name, len(hits))
}

// AliasDoc is one alias's entries at one version.
type AliasDoc struct {
	output.Header
	Alias   ncfapi.AliasInfo `json:"alias"`
	Version string           `json:"version" doc:"The version shown: the alias's active version unless --version named another."`
	Active  bool             `json:"active" doc:"The shown version is the alias's active version."`
	Managed bool             `json:"managed" doc:"The alias is Akamai-managed (not customer-editable); its entries were fetched because it was named explicitly."`
	Entries []string         `json:"entries" doc:"Canonical form where parsable (others kept as sent); sorted IPv4, IPv6, GEO, ASN, then unparsable."`
}

func (*AliasDoc) SchemaID() string { return "prolexic.alias.v1" }

func (d *AliasDoc) WriteText(w io.Writer) error {
	al := d.Alias
	kind := "customer-editable"
	if d.Managed {
		kind = "Akamai-managed, read-only"
	}
	fmt.Fprintf(w, "%s (id %d, %s %s, %s): version %s", al.Name, al.ID, al.Type, al.IPVersion, kind, d.Version)
	if d.Active {
		fmt.Fprint(w, " (active)")
	}
	fmt.Fprintf(w, ", %d entries\n", len(d.Entries))
	for _, e := range d.Entries {
		if _, err := fmt.Fprintln(w, e); err != nil {
			return err
		}
	}
	return nil
}

// normaliseEntries canonicalises parsable entries and sorts them with
// ncf.Compare; entries that don't parse are kept as sent and follow, sorted.
func normaliseEntries(raw []string) []string {
	var good []ncf.Value
	var bad []string
	for _, s := range raw {
		if v, err := ncf.ParseLive(s); err == nil {
			good = append(good, v)
		} else {
			bad = append(bad, s)
		}
	}
	slices.SortStableFunc(good, ncf.Compare)
	slices.Sort(bad)
	out := make([]string, 0, len(raw))
	for _, v := range good {
		out = append(out, v.String())
	}
	return append(out, bad...)
}

func newAliasesShowCmd(a *app) *cobra.Command {
	var name, version string
	var id int64
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one alias's entries at a version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return aliasesShow(ctx, a, name, id, version)
		}),
	}
	aliasSelector(cmd, &name, &id)
	cmd.Flags().StringVar(&version, "version", "", "version id, e.g. V3 (default: the alias's active version)")
	return cmd
}

// aliasSelector is the --name/--id pair that picks one alias.
func aliasSelector(cmd *cobra.Command, name *string, id *int64) {
	cmd.Flags().StringVar(name, "name", "", "alias name")
	cmd.Flags().Int64Var(id, "id", 0, "alias id")
}

func aliasesShow(ctx context.Context, a *app, name string, id int64, version string) (output.Document, error) {
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	al, err := resolveAlias(ctx, api, name, id)
	if err != nil {
		return nil, err
	}
	v := cmp.Or(version, al.ActiveVersion)
	if v == "" {
		return nil, apperr.New(apperr.Upstream, "alias %s lists no active version; name one with --version", al.Name)
	}
	// Live /versions/active carries no entries, so the active version is
	// read by its id.
	got, err := api.GetVersion(ctx, al.ID, v)
	if err != nil {
		return nil, err
	}
	return &AliasDoc{
		Alias: al, Version: cmp.Or(got.Version, v), Active: v == al.ActiveVersion, Managed: !al.Editable,
		Entries: normaliseEntries(got.Entries),
	}, nil
}

func joinInts(n []int) string {
	s := make([]string, len(n))
	for i, v := range n {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}
