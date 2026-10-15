package cli

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"text/tabwriter"
	"time"

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

func runTimeSeries(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	var dests, locs stringList
	fs.Var(&dests, "destination", "address or CIDR block (required); repeatable or comma-separated")
	fs.Var(&locs, "location", "data center such as mia4, or agr for all aggregated; repeatable or comma-separated (default: agr)")
	source := fs.String("source", "both", "router type: both, access_flow (Akamai router) or border_flow (customer router)")
	sum := fs.Bool("sum", false, "also return the aggregatedData facet")
	samples := fs.Int("samples", 0, "number of timestamps to return (default: all in the window)")
	var win windowFlags
	win.register(fs, 2*time.Hour)
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	if len(dests) == 0 {
		return nil, apperr.New(apperr.Usage, "--destination is required\n%s", flagUsage(fs))
	}
	for _, d := range dests {
		if _, err := analytics.ParsePrefix(d); err != nil {
			return nil, apperr.New(apperr.Usage, "--destination %q: not an address or CIDR block", d)
		}
	}
	if len(locs) == 0 {
		locs = stringList{"agr"}
	}
	for _, l := range locs {
		if !locationRE.MatchString(l) {
			return nil, apperr.New(apperr.Usage, "--location %q: want a data center like mia4, or agr", l)
		}
	}
	switch *source {
	case "both", "access_flow", "border_flow":
	default:
		return nil, apperr.New(apperr.Usage, "--source %q: want both, access_flow or border_flow", *source)
	}
	if *samples < 0 {
		return nil, apperr.New(apperr.Usage, "--samples can't be negative")
	}
	start, end, _, err := win.resolve(fs, a.env.Now())
	if err != nil {
		return nil, err
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	pts, err := api.TimeSeries(ctx, analytics.TimeSeriesQuery{
		Destinations: dests, Locations: locs, Source: *source, Sum: *sum, Samples: *samples, Start: start, End: end,
	})
	if err != nil {
		return nil, err
	}
	return &TimeSeriesDoc{
		Destinations: dests, Locations: locs, Source: *source,
		Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339), Points: nonNil(pts),
	}, nil
}
