package cli

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// TimeSeriesDoc is flow-based usage and attack traffic for destinations.
type TimeSeriesDoc struct {
	output.Header
	Destinations []string                    `json:"destinations" doc:"The addresses or CIDR blocks queried."`
	Locations    []string                    `json:"locations" doc:"The data centers queried; agr is all of them, aggregated."`
	Source       string                      `json:"source" doc:"both, access_flow (Akamai router) or border_flow (customer router)."`
	Start        string                      `json:"start" doc:"Window start, RFC 3339 UTC."`
	End          string                      `json:"end" doc:"Window end, RFC 3339 UTC."`
	Points       []analytics.TimeSeriesPoint `json:"points" doc:"Sorted by destination, facet, time."`
}

func (*TimeSeriesDoc) SchemaID() string { return "prolexic.time-series.v1" }

func (d *TimeSeriesDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DESTINATION\tFACET\tTIME\tVALUE")
	for _, p := range d.Points {
		at := p.Key
		if p.Time > 0 {
			at = epoch(p.Time)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%g\n", p.Destination, p.Facet, at, float64(p.Value))
	}
	return tw.Flush()
}

// locationRE is the API's own pattern for one location.
var locationRE = regexp.MustCompile(`^([a-z]{3}[0-9]|agr)$`)

func newTimeSeriesCmd(a *app) *cobra.Command {
	var dests, locs []string
	var source string
	var sum bool
	var samples int
	var win windowFlags
	cmd := &cobra.Command{
		Use:     "time-series",
		Short:   "flow usage and attack traffic per destination (read-only)",
		Example: "  prolexic time-series --destination 198.51.100.0/24 --location agr --since 2h",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return timeSeries(ctx, a, dests, locs, source, sum, samples, win)
		}),
	}
	f := cmd.Flags()
	f.StringSliceVar(&dests, "destination", nil, "address or CIDR block (required); repeatable or comma-separated")
	f.StringSliceVar(&locs, "location", nil, "data center such as mia4, or agr for all aggregated; repeatable or comma-separated (default: agr)")
	f.StringVar(&source, "source", "both", "router type: both, access_flow (Akamai router) or border_flow (customer router)")
	f.BoolVar(&sum, "sum", false, "also return the aggregatedData facet")
	f.IntVar(&samples, "samples", 0, "number of timestamps to return (default: all in the window)")
	win.register(cmd, 2*time.Hour)
	_ = cmd.MarkFlagRequired("destination")
	return cmd
}

func timeSeries(ctx context.Context, a *app, dests, locs []string, source string, sum bool, samples int, win windowFlags) (output.Document, error) {
	if len(dests) == 0 {
		return nil, apperr.New(apperr.Usage, "--destination is required")
	}
	for _, d := range dests {
		if _, err := analytics.ParsePrefix(d); err != nil {
			return nil, apperr.New(apperr.Usage, "--destination %q: not an address or CIDR block", d)
		}
	}
	if len(locs) == 0 {
		locs = []string{"agr"}
	}
	for _, l := range locs {
		if !locationRE.MatchString(l) {
			return nil, apperr.New(apperr.Usage, "--location %q: want a data center like mia4, or agr", l)
		}
	}
	switch source {
	case "both", "access_flow", "border_flow":
	default:
		return nil, apperr.New(apperr.Usage, "--source %q: want both, access_flow or border_flow", source)
	}
	if samples < 0 {
		return nil, apperr.New(apperr.Usage, "--samples can't be negative")
	}
	start, end, _, err := win.resolve(a.env.Now())
	if err != nil {
		return nil, err
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	pts, err := api.TimeSeries(ctx, analytics.TimeSeriesQuery{
		Destinations: dests, Locations: locs, Source: source, Sum: sum, Samples: samples, Start: start, End: end,
	})
	if err != nil {
		return nil, err
	}
	return &TimeSeriesDoc{
		Destinations: dests, Locations: locs, Source: source,
		Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339), Points: nonNil(pts),
	}, nil
}
