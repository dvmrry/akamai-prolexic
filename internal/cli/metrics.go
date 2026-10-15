package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
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

// metricServices are the non-FBM services of the request and their metrics.
var metricServices = map[string][]string{
	"connect":        {"bandwidthIn", "packetsIn"},
	"mitigationPost": {"packets", "bandwidth"},
	"mitigationPre":  {"packets", "bandwidth"},
	"proxy":          {"latency", "bandwidthIn", "bandwidthOut", "connections", "packetsOut", "requests", "packetsIn"},
	"routed":         {"bandwidthIn", "packetsIn"},
}

var fbmProtocols = []string{"total", "icmp", "igmp", "udp", "tcp"}

const typeHelp = "SERVICE:METRIC, or fbm:METRIC:PROTOCOL (repeatable or comma-separated); e.g. routed:bandwidthIn, fbm:bandwidth:total"

// parseMetricTypes turns --type values into the request's type object.
func parseMetricTypes(types []string, subnet, ip string) (map[string][]string, []analytics.FBMMetric, error) {
	if len(types) == 0 {
		return nil, nil, apperr.New(apperr.Usage, "--type is required: %s", typeHelp)
	}
	if subnet != "" && ip != "" {
		return nil, nil, apperr.New(apperr.Usage, "--subnet and --ip are exclusive")
	}
	services := map[string][]string{}
	var fbm []analytics.FBMMetric
	for _, t := range types {
		parts := strings.Split(t, ":")
		svc := parts[0]
		if svc == "fbm" {
			if len(parts) != 3 || !slices.Contains([]string{"bandwidth", "packets"}, parts[1]) || !slices.Contains(fbmProtocols, parts[2]) {
				return nil, nil, apperr.New(apperr.Usage, "--type %q: want fbm:bandwidth|packets:%s", t, strings.Join(fbmProtocols, "|"))
			}
			m := analytics.FBMMetric{Metric: parts[1], Protocol: parts[2], Subnet: subnet, IP: ip}
			if !slices.Contains(fbm, m) {
				fbm = append(fbm, m)
			}
			continue
		}
		allowed, ok := metricServices[svc]
		if !ok || len(parts) != 2 || !slices.Contains(allowed, parts[1]) {
			return nil, nil, apperr.New(apperr.Usage, "--type %q: want %s", t, typeHelp)
		}
		if !slices.Contains(services[svc], parts[1]) {
			services[svc] = append(services[svc], parts[1])
		}
	}
	if (subnet != "" || ip != "") && len(fbm) == 0 {
		return nil, nil, apperr.New(apperr.Usage, "--subnet and --ip apply to fbm types only")
	}
	for _, ms := range services {
		slices.Sort(ms)
	}
	slices.SortFunc(fbm, func(x, y analytics.FBMMetric) int {
		return cmp.Or(cmp.Compare(x.Metric, y.Metric), cmp.Compare(x.Protocol, y.Protocol))
	})
	return services, fbm, nil
}

func newMetricsCmd(a *app) *cobra.Command {
	var customers, types []string
	var subnet, ip string
	var samples int
	var win windowFlags
	cmd := &cobra.Command{
		Use:     "metrics",
		Short:   "traffic metrics per customer name (read-only)",
		Example: "  prolexic metrics --type routed:bandwidthIn --since 6h",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return metrics(ctx, a, customers, types, subnet, ip, samples, win)
		}),
	}
	f := cmd.Flags()
	listVar(f, &customers, "customer", "customer name (the API's contract) to query; repeatable or comma-separated (default: every in-use name)")
	listVar(f, &types, "type", typeHelp)
	f.StringVar(&subnet, "subnet", "", "restrict fbm types to one subnet")
	f.StringVar(&ip, "ip", "", "restrict fbm types to one IP address")
	f.IntVar(&samples, "samples", 100, "number of data points to return")
	win.register(cmd, 24*time.Hour)
	return cmd
}

func metrics(ctx context.Context, a *app, customers, types []string, subnet, ip string, samples int, win windowFlags) (output.Document, error) {
	services, fbm, err := parseMetricTypes(types, subnet, ip)
	if err != nil {
		return nil, err
	}
	if samples < 1 {
		return nil, apperr.New(apperr.Usage, "--samples must be at least 1")
	}
	start, end, _, err := win.resolve(a.env.Now())
	if err != nil {
		return nil, err
	}
	if end.Sub(start) > analytics.MetricsMaxSpan {
		return nil, apperr.New(apperr.Usage, "the window is longer than the API's maximum of 90 days")
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}
	q := analytics.MetricQuery{Services: services, FBM: fbm, Start: start, End: end, Samples: samples}
	rows, failures, err := analytics.FanOut(ctx, names, func(ctx context.Context, name string) ([]analytics.MetricSeries, error) {
		return api.Metrics(ctx, name, q)
	})
	if ctx.Err() != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y analytics.MetricSeries) int {
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
		Customers: names, Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339),
		Series: nonNil(rows), Failures: nonNil(failures),
	}, err
}
