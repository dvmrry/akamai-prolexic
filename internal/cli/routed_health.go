package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

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

func newRoutedHealthCmd(a *app) *cobra.Command {
	var customers []string
	cmd := &cobra.Command{
		Use:   "health",
		Short: "healthy and total tunnels per location and router",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return routedHealth(ctx, a, customers)
		}),
	}
	customerFlag(cmd, &customers)
	return cmd
}

func routedHealth(ctx context.Context, a *app, customers []string) (output.Document, error) {
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}
	rows, failures, err := analytics.FanOut(ctx, names, api.TunnelHealth)
	if ctx.Err() != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y analytics.TunnelHealth) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.AkamaiLocation, y.AkamaiLocation),
			cmp.Compare(x.RouterName, y.RouterName),
		)
	})
	return &RoutedHealthDoc{Customers: names, Health: nonNil(rows), Failures: nonNil(failures)}, err
}
