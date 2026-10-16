package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
	"time"

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

// MetricsDefaultSince is the window Metrics reads when none is given;
// MetricsDefaultSamples is the usual sample count, which fronts offer as the
// default (Metrics never assumes it).
const (
	MetricsDefaultSince   = 24 * time.Hour
	MetricsDefaultSamples = 100
)

// MetricsInput queries traffic metrics.
type MetricsInput struct {
	Customers []string // customer names (the API's contract); empty means every in-use name
	Types     []string // SERVICE:METRIC, or fbm:METRIC:PROTOCOL; required
	Subnet    string   // the subnet fbm types report on; fbm types need a subnet or an ip
	IP        string   // the IP address fbm types report on
	Samples   int      // data points to return, at least 1
	Window    Window   // zero means the last MetricsDefaultSince
}

// Metrics queries traffic metrics per customer name; a name whose query
// failed is reported in the document, not as an error.
func (r *Runtime) Metrics(ctx context.Context, in MetricsInput) (*MetricsDoc, error) {
	start, end, _, err := in.Window.resolve(r.now(), MetricsDefaultSince)
	if err != nil {
		return nil, err
	}
	q, err := analytics.ParseMetricQuery(in.Types, in.Subnet, in.IP, start, end, in.Samples)
	if err != nil {
		return nil, err
	}
	api, err := r.analyticsFor(in.Customers)
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, in.Customers, func(ctx context.Context, name string) ([]analytics.MetricSeries, error) {
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
