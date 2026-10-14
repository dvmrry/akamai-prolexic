package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// StatusDeployment is the account's ACL deployment state.
type StatusDeployment struct {
	Version     int    `json:"version" doc:"The ACL version in production."`
	State       string `json:"state" doc:"PRODUCTION, PROCESSING or FAILED; empty when the API reported none."`
	FailedRules int    `json:"failedRules" doc:"Rules that failed to install; non-zero is a partial failure."`
	Processing  bool   `json:"processing" doc:"A version is being staged."`
}

// StatusAlias is one live alias, from the list call only (no entries).
type StatusAlias struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	IPVersion         string `json:"ipVersion"`
	Editable          bool   `json:"editable" doc:"False means Akamai-managed."`
	EntriesCount      int    `json:"entriesCount"`
	ActiveVersion     int    `json:"activeVersion" doc:"0 when the API doesn't expose versions."`
	ProdVersion       int    `json:"prodVersion" doc:"The version production carries; differs from activeVersion while an activation is pending."`
	VersionsRemaining *int   `json:"versionsRemaining,omitempty" doc:"Versions left before the alias is full; absent when the API doesn't expose versions."`
}

// StatusLimit is the account's alias limit for one type.
type StatusLimit struct {
	Type     string `json:"type"`
	Limit    int    `json:"limit"`
	Enabled  int    `json:"enabled"`
	Disabled int    `json:"disabled"`
}

// StatusDoc is the account's firewall state: deployment, aliases, limits.
type StatusDoc struct {
	output.Header
	Deployment StatusDeployment `json:"deployment"`
	Aliases    []StatusAlias    `json:"aliases" doc:"Sorted by name."`
	Limits     []StatusLimit    `json:"limits" doc:"Sorted by type."`
}

func (*StatusDoc) SchemaID() string { return "prolexic.status.v1" }

// lowVersions is the versionsRemaining below which text output warns.
const lowVersions = 3

func (d *StatusDoc) WriteText(w io.Writer) error {
	dep := d.Deployment
	fmt.Fprintf(w, "deployment: version %d, state %s, %d failed rules", dep.Version, dash(dep.State), dep.FailedRules)
	if dep.Processing {
		fmt.Fprint(w, ", PROCESSING a new version")
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nNAME\tID\tTYPE\tIP\tEDITABLE\tENTRIES\tACTIVE\tPROD\tVERSIONS LEFT\t")
	for _, al := range d.Aliases {
		left, mark := "-", ""
		if al.VersionsRemaining != nil {
			left = fmt.Sprint(*al.VersionsRemaining)
			if *al.VersionsRemaining < lowVersions {
				mark += "LOW VERSIONS "
			}
		}
		if al.ActiveVersion != al.ProdVersion {
			mark += "ACTIVATION PENDING"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%t\t%d\t%d\t%d\t%s\t%s\n", al.Name, al.ID, al.Type, al.IPVersion, al.Editable,
			al.EntriesCount, al.ActiveVersion, al.ProdVersion, left, mark)
	}
	fmt.Fprintln(tw, "\nLIMIT TYPE\tLIMIT\tENABLED\tDISABLED\t\t\t\t\t\t")
	for _, l := range d.Limits {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", l.Type, l.Limit, l.Enabled, l.Disabled)
	}
	return tw.Flush()
}

func runStatus(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	store, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	dep, err := store.Deployment(ctx)
	if err != nil {
		return nil, err
	}
	// ListAliases only: GetAlias would fetch entries, and managed aliases
	// can hold 100k+ of them.
	live, err := store.ListAliases(ctx)
	if err != nil {
		return nil, err
	}
	limits, err := store.Limits(ctx)
	if err != nil {
		return nil, err
	}
	doc := &StatusDoc{
		Deployment: StatusDeployment{Version: dep.Version, State: dep.State, FailedRules: dep.FailedRules, Processing: dep.Processing},
		Aliases:    []StatusAlias{},
		Limits:     []StatusLimit{},
	}
	for _, l := range live {
		al := StatusAlias{
			ID: l.ID, Name: l.Name, Type: l.Type, IPVersion: l.IPVersion, Editable: l.Editable,
			EntriesCount: l.EntriesCount, ActiveVersion: l.ActiveVersion, ProdVersion: l.ProdVersion,
		}
		if l.Versions > 0 {
			rem := max(ncf.MaxVersions-l.Versions, 0)
			al.VersionsRemaining = &rem
		}
		doc.Aliases = append(doc.Aliases, al)
	}
	slices.SortStableFunc(doc.Aliases, func(x, y StatusAlias) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.ID, y.ID))
	})
	for _, l := range limits {
		doc.Limits = append(doc.Limits, StatusLimit{Type: l.Type, Limit: l.Limit, Enabled: l.Enabled, Disabled: l.Disabled})
	}
	slices.SortStableFunc(doc.Limits, func(x, y StatusLimit) int { return cmp.Compare(x.Type, y.Type) })
	return doc, nil
}
