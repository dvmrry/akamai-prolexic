package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

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

// AliasesInput selects which aliases to list.
type AliasesInput struct {
	EditableOnly bool // only customer-editable aliases (not Akamai-managed)
}

// Aliases lists every alias of the account, without entries.
func (r *Runtime) Aliases(ctx context.Context, in AliasesInput) (*AliasesDoc, error) {
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	rows, err := api.ListAliasInfo(ctx)
	if err != nil {
		return nil, err
	}
	if in.EditableOnly {
		rows = slices.DeleteFunc(rows, func(r ncfapi.AliasInfo) bool { return !r.Editable })
	}
	slices.SortStableFunc(rows, func(x, y ncfapi.AliasInfo) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.ID, y.ID))
	})
	return &AliasesDoc{Aliases: nonNil(rows)}, nil
}

// resolveAlias finds the one alias named by name or id.
func resolveAlias(ctx context.Context, api *ncfapi.V2, name string, id int64) (ncfapi.AliasInfo, error) {
	if (name == "") == (id == 0) {
		return ncfapi.AliasInfo{}, apperr.New(apperr.Usage, "give exactly one of the alias name and the alias id")
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
	return ncfapi.AliasInfo{}, apperr.New(apperr.Upstream, "alias name %q is ambiguous: %d aliases carry it; use the alias id", name, len(hits))
}

// AliasDoc is one alias's entries at one version.
type AliasDoc struct {
	output.Header
	Alias   ncfapi.AliasInfo `json:"alias"`
	Version string           `json:"version" doc:"The version shown: the alias's active version unless another was named."`
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

// AliasInput names one alias and, optionally, a version of it.
type AliasInput struct {
	Name    string // the alias name; give exactly one of Name and ID
	ID      int64  // the alias id
	Version string // the version id, e.g. V3; empty means the alias's active version
}

// Alias is one alias's entries at a version.
func (r *Runtime) Alias(ctx context.Context, in AliasInput) (*AliasDoc, error) {
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	al, err := resolveAlias(ctx, api, in.Name, in.ID)
	if err != nil {
		return nil, err
	}
	v := cmp.Or(in.Version, al.ActiveVersion)
	if v == "" {
		return nil, apperr.New(apperr.Upstream, "alias %s lists no active version; name a version", al.Name)
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
