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

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ProtectedDoc is what `plan` treats as own space, per customer name.
type ProtectedDoc struct {
	output.Header
	Customers []string              `json:"customers" doc:"The customer names queried (every name of the account unless --customer is given)."`
	Protected []analytics.Protected `json:"protected" doc:"One row per customer name, sorted by customer."`
	Failures  []analytics.Failure   `json:"failures" doc:"Customer names whose query failed."`
}

func (*ProtectedDoc) SchemaID() string { return "prolexic.protected.v1" }

func (d *ProtectedDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tSITE\tPREFIXES\tASNS\tNOTES")
	for _, p := range d.Protected {
		var prefixes, asns []string
		for _, x := range p.Prefixes {
			prefixes = append(prefixes, x.String())
		}
		for _, n := range p.ASNs {
			asns = append(asns, strconv.FormatInt(n, 10))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Customer, dash(p.Site), dash(strings.Join(prefixes, ",")),
			dash(strings.Join(asns, ",")), dash(strings.Join(p.Notes, "; ")))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

func newProtectedCmd(a *app) *cobra.Command {
	var customers []string
	cmd := &cobra.Command{
		Use:   "protected",
		Short: "prefixes and AS numbers treated as own space, per customer name (read-only)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return protected(ctx, a, customers)
		}),
	}
	cmd.Flags().StringSliceVar(&customers, "customer", nil, "customer name to query; repeatable or comma-separated (default: every name, in use or not)")
	return cmd
}

func protected(ctx context.Context, a *app, customers []string) (output.Document, error) {
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.AllCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}
	rows, failures, err := analytics.FanOut(ctx, names, func(ctx context.Context, name string) ([]analytics.Protected, error) {
		p, err := api.ProtectedFor(ctx, name)
		return []analytics.Protected{p}, err
	})
	if ctx.Err() != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y analytics.Protected) int { return cmp.Compare(x.Customer, y.Customer) })
	return &ProtectedDoc{Customers: names, Protected: nonNil(rows), Failures: nonNil(failures)}, err
}
