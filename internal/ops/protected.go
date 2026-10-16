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

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ProtectedDoc is what `plan` treats as own space, per customer name.
type ProtectedDoc struct {
	output.Header
	Customers []string              `json:"customers" doc:"The customer names queried (every name of the account unless customers are given)."`
	Protected []analytics.Protected `json:"protected" doc:"One row per customer name, sorted by customer."`
	Failures  []analytics.Failure   `json:"failures" doc:"Customer names whose query failed."`
}

func (*ProtectedDoc) SchemaID() string { return "prolexic.protected.v1" }

func (d *ProtectedDoc) Outcome() error { return failuresOutcome(d.Failures, d.Customers) }

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

// ProtectedInput reads what is treated as own space.
type ProtectedInput struct {
	Customers []string // customer names; empty means every name, in use or not
}

// Protected reads the prefixes and AS numbers treated as own space, per
// customer name; a name whose query failed is reported in the document, not
// as an error.
func (r *Runtime) Protected(ctx context.Context, in ProtectedInput) (*ProtectedDoc, error) {
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.AllCustomers, in.Customers, func(ctx context.Context, name string) ([]analytics.Protected, error) {
		p, err := api.ProtectedFor(ctx, name)
		return []analytics.Protected{p}, err
	})
	if res == nil {
		return nil, err
	}
	slices.SortStableFunc(res.Rows, func(x, y analytics.Protected) int { return cmp.Compare(x.Customer, y.Customer) })
	return &ProtectedDoc{Customers: res.Customers, Protected: res.Rows, Failures: res.Failures}, nil
}
