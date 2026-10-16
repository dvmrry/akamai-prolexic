package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// MetricsDoc is traffic metrics across customer names.
type MetricsDoc struct {
	output.Header
	Customers []string                 `json:"customers" doc:"The customer names queried."`
	Start     string                   `json:"start" doc:"Window start, RFC 3339 UTC."`
	End       string                   `json:"end" doc:"Window end, RFC 3339 UTC."`
	Series    []analytics.MetricSeries `json:"series" doc:"Sorted by customer, service, metric, protocol, subnet, ip."`
	Failures  []analytics.Failure      `json:"failures" doc:"Customer names whose query failed."`
}

func (*MetricsDoc) SchemaID() string { return "prolexic.metrics.v1" }

func (d *MetricsDoc) Outcome() error { return failuresOutcome(d.Failures, d.Customers) }

func (d *MetricsDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tSERVICE\tMETRIC\tPROTOCOL\tTARGET\tPOINTS\tLAST")
	for _, s := range d.Series {
		last := "-"
		if n := len(s.Points); n > 0 && len(s.Points[n-1]) > 1 {
			last = fmt.Sprintf("%g", float64(s.Points[n-1][1]))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", s.Customer, dash(s.Service), s.Metric, dash(s.Protocol),
			dash(cmp.Or(s.Subnet, s.IP)), len(s.Points), last)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

const typeHelp = "SERVICE:METRIC, or fbm:METRIC:PROTOCOL (repeatable or comma-separated); e.g. routed:bandwidthIn, fbm:bandwidth:total"

func newMetricsCmd(a *app) *cobra.Command {
	var customers, types []string
	var subnet, ip string
	var samples int
	var win windowFlags
	cmd := &cobra.Command{
		Use:     "metrics",
		Short:   "traffic metrics per customer name",
		Example: "  prolexic metrics --type routed:bandwidthIn --since 6h",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return metrics(ctx, a, customers, types, subnet, ip, samples, win)
		}),
	}
	f := cmd.Flags()
	listVar(f, &customers, "customer", "customer name (the API's contract) to query; repeatable or comma-separated (default: every in-use name)")
	listVar(f, &types, "type", typeHelp)
	f.StringVar(&subnet, "subnet", "", "the subnet fbm types report on (fbm types need --subnet or --ip)")
	f.StringVar(&ip, "ip", "", "the IP address fbm types report on (fbm types need --subnet or --ip)")
	f.IntVar(&samples, "samples", 100, "number of data points to return")
	win.register(cmd, 24*time.Hour)
	return cmd
}

func metrics(ctx context.Context, a *app, customers, types []string, subnet, ip string, samples int, win windowFlags) (output.Document, error) {
	start, end, _, err := win.resolve(a.env.Now())
	if err != nil {
		return nil, err
	}
	q, err := analytics.ParseMetricQuery(types, subnet, ip, start, end, samples)
	if err != nil {
		return nil, err
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, customers, func(ctx context.Context, name string) ([]analytics.MetricSeries, error) {
		return api.Metrics(ctx, name, q)
	})
	if res == nil {
		return nil, err
	}
	slices.SortStableFunc(res.Rows, func(x, y analytics.MetricSeries) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.Service, y.Service),
			cmp.Compare(x.Metric, y.Metric),
			cmp.Compare(x.Protocol, y.Protocol),
			cmp.Compare(x.Subnet, y.Subnet),
			cmp.Compare(x.IP, y.IP),
		)
	})
	return &MetricsDoc{
		Customers: res.Customers, Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339),
		Series: res.Rows, Failures: res.Failures,
	}, nil
}
