package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// RoutedRoutesDoc lists the routes customer routers announce to Akamai.
type RoutedRoutesDoc struct {
	output.Header
	Customers []string            `json:"customers" doc:"The customer names queried."`
	Prefix    string              `json:"prefix,omitempty" doc:"The normalised --prefix filter, when given."`
	Routes    []analytics.Route   `json:"routes" doc:"Sorted by customer, prefix, dataCenter, routerName, customerBgpPeerIp."`
	Failures  []analytics.Failure `json:"failures" doc:"Customer names whose query failed."`
}

func (*RoutedRoutesDoc) SchemaID() string { return "prolexic.routed-routes.v1" }

func (d *RoutedRoutesDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tPREFIX\tDATA CENTER\tROUTER\tPEER\tAS PATH\tLOCAL PREF\tMED")
	for _, r := range d.Routes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Customer, r.Prefix, dash(r.DataCenter), r.RouterName,
			r.CustomerBgpPeerIp, dash(r.ASPath), optInt(r.LocalPref), optInt(r.MED))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

func optInt(p *int64) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprint(*p)
}

func runRoutedRoutes(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	var customers stringList
	fs.Var(&customers, "customer", "customer name to query; repeatable or comma-separated (default: every in-use name)")
	prefix := fs.String("prefix", "", "only routes for exactly this prefix (a bare address means /32 or /128)")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	var want netip.Prefix
	if *prefix != "" {
		p, err := analytics.ParsePrefix(*prefix)
		if err != nil {
			return nil, err
		}
		want = p
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}
	rows, failures, err := analytics.FanOut(ctx, names, api.Routes)
	if ctx.Err() != nil {
		return nil, err
	}
	if want.IsValid() {
		rows = slices.DeleteFunc(rows, func(r analytics.Route) bool { return !analytics.SamePrefix(r.Prefix, want) })
	}
	slices.SortStableFunc(rows, func(x, y analytics.Route) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.Prefix, y.Prefix),
			cmp.Compare(x.DataCenter, y.DataCenter),
			cmp.Compare(x.RouterName, y.RouterName),
			cmp.Compare(x.CustomerBgpPeerIp, y.CustomerBgpPeerIp),
		)
	})
	doc := &RoutedRoutesDoc{Customers: names, Routes: nonNil(rows), Failures: nonNil(failures)}
	if want.IsValid() {
		doc.Prefix = want.String()
	}
	return doc, err
}
