package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// StatusDeployment is the account's ACL deployment state.
type StatusDeployment struct {
	Version       int    `json:"version" doc:"The ACL version in production."`
	State         string `json:"state" doc:"PRODUCTION, PROCESSING or FAILED; empty when the API reported none."`
	FailedRules   int    `json:"failedRules" doc:"Rules that failed to install; non-zero is a partial failure."`
	Processing    bool   `json:"processing" doc:"A version is being staged."`
	FailedVersion int    `json:"failedVersion,omitempty" doc:"The newest FAILED ruleset; at or after the production version it means the deployment failed."`
}

// StatusAlias is one live alias, from the list call only (no entries).
type StatusAlias struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	IPVersion     string `json:"ipVersion"`
	Editable      bool   `json:"editable" doc:"False means Akamai-managed."`
	EntriesCount  int    `json:"entriesCount"`
	ActiveVersion string `json:"activeVersion" doc:"Empty when the API doesn't expose versions."`
	ProdVersion   string `json:"prodVersion" doc:"The version production carries; differs from activeVersion while an activation is pending."`
}

// StatusLimit is the alias limit for one type. The counts cover customer-editable
// aliases only, not account totals.
type StatusLimit struct {
	Type     string `json:"type"`
	Limit    int    `json:"limit" doc:"The alias limit for the type; /stats counts customer-editable aliases only, not account totals."`
	Enabled  int    `json:"enabled" doc:"Enabled customer-editable aliases of the type (not an account total)."`
	Disabled int    `json:"disabled" doc:"Disabled customer-editable aliases of the type (not an account total)."`
}

// StatusDoc is the account's firewall state: deployment, aliases, limits.
type StatusDoc struct {
	output.Header
	Deployment StatusDeployment `json:"deployment"`
	Aliases    []StatusAlias    `json:"aliases" doc:"Sorted by name."`
	Limits     []StatusLimit    `json:"limits" doc:"Sorted by type. Counts cover customer-editable aliases only, not account totals."`
}

func (*StatusDoc) SchemaID() string { return "prolexic.status.v1" }

func (d *StatusDoc) WriteText(w io.Writer) error {
	dep := d.Deployment
	fmt.Fprintf(w, "deployment: version %d, state %s, %d failed rules", dep.Version, dash(dep.State), dep.FailedRules)
	if dep.Processing {
		fmt.Fprint(w, ", PROCESSING a new version")
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nNAME\tID\tTYPE\tIP\tEDITABLE\tENTRIES\tACTIVE\tPROD\t")
	for _, al := range d.Aliases {
		mark := ""
		if al.ActiveVersion != al.ProdVersion {
			mark += "ACTIVATION PENDING"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%t\t%d\t%s\t%s\t%s\n", al.Name, al.ID, al.Type, al.IPVersion, al.Editable,
			al.EntriesCount, dash(al.ActiveVersion), dash(al.ProdVersion), mark)
	}
	fmt.Fprintln(tw, "\nLIMIT TYPE (customer-editable aliases)\tLIMIT\tENABLED\tDISABLED\t\t\t\t\t")
	for _, l := range d.Limits {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", l.Type, l.Limit, l.Enabled, l.Disabled)
	}
	return tw.Flush()
}

func newStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "deployment state, aliases and limits (read-only)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return status(ctx, a)
		}),
	}
}

func status(ctx context.Context, a *app) (output.Document, error) {
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
		Deployment: StatusDeployment{Version: dep.Version, State: dep.State, FailedRules: dep.FailedRules, Processing: dep.Processing, FailedVersion: dep.FailedVersion},
		Aliases:    []StatusAlias{},
		Limits:     []StatusLimit{},
	}
	for _, l := range live {
		al := StatusAlias{
			ID: l.ID, Name: l.Name, Type: l.Type, IPVersion: l.IPVersion, Editable: l.Editable,
			EntriesCount: l.EntriesCount, ActiveVersion: l.ActiveVersion, ProdVersion: l.ProdVersion,
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
