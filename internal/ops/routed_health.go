package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// RoutedHealthDoc lists healthy and total tunnels per Akamai location and
// customer router.
type RoutedHealthDoc struct {
	output.Header
	Customers []string                 `json:"customers" doc:"The customer names queried."`
	Health    []analytics.TunnelHealth `json:"health" doc:"Sorted by customer, akamaiLocation, routerName."`
	Failures  []analytics.Failure      `json:"failures" doc:"Customer names whose query failed."`
}

func (*RoutedHealthDoc) SchemaID() string { return "prolexic.routed-health.v1" }

func (d *RoutedHealthDoc) Outcome() error { return failuresOutcome(d.Failures, d.Customers) }

func (d *RoutedHealthDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tLOCATION\tROUTER\tHEALTHY/TOTAL\tADC HEALTHY/TOTAL\t")
	for _, h := range d.Health {
		mark := ""
		if !h.Healthy() {
			mark = "UNHEALTHY"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d/%d\t%d/%d\t%s\n", h.Customer, h.AkamaiLocation, h.RouterName,
			h.HealthyFunnels, h.TotalFunnels, h.HealthyAdcFunnels, h.TotalAdcFunnels, mark)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

// RoutedHealthInput lists tunnel health.
type RoutedHealthInput struct {
	Customers []string // customer names; empty means every in-use name
}

// RoutedHealth lists healthy and total tunnels per location and router; a
// name whose query failed is reported in the document, not as an error.
func (r *Runtime) RoutedHealth(ctx context.Context, in RoutedHealthInput) (*RoutedHealthDoc, error) {
	api, err := r.analyticsFor(in.Customers)
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, in.Customers, api.TunnelHealth)
	if res == nil {
		return nil, err
	}
	slices.SortStableFunc(res.Rows, func(x, y analytics.TunnelHealth) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.AkamaiLocation, y.AkamaiLocation),
			cmp.Compare(x.RouterName, y.RouterName),
		)
	})
	return &RoutedHealthDoc{Customers: res.Customers, Health: res.Rows, Failures: res.Failures}, nil
}
