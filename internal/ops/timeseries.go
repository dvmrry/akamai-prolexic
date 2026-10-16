package ops

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
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

// TimeSeriesDefaultSince is the window TimeSeries reads when none is given;
// TimeSeriesDefaultSource is the usual source, which fronts offer as the
// default (TimeSeries never assumes it).
const (
	TimeSeriesDefaultSince  = 2 * time.Hour
	TimeSeriesDefaultSource = "both"
)

// TimeSeriesInput queries flow usage and attack traffic.
type TimeSeriesInput struct {
	Destinations []string // addresses or CIDR blocks; required
	Locations    []string // data centers such as mia4, or agr for all aggregated; empty means agr
	Source       string   // both, access_flow or border_flow; required
	Sum          bool     // also return the aggregatedData facet
	Samples      int      // timestamps to return; zero means all in the window
	Window       Window   // zero means the last TimeSeriesDefaultSince
}

// TimeSeries reads flow-based usage and attack traffic for destinations.
func (r *Runtime) TimeSeries(ctx context.Context, in TimeSeriesInput) (*TimeSeriesDoc, error) {
	start, end, _, err := in.Window.resolve(r.now(), TimeSeriesDefaultSince)
	if err != nil {
		return nil, err
	}
	q, err := analytics.ParseTimeSeriesQuery(in.Destinations, in.Locations, in.Source, in.Sum, in.Samples, start, end)
	if err != nil {
		return nil, err
	}
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	pts, err := api.TimeSeries(ctx, q)
	if err != nil {
		return nil, err
	}
	return &TimeSeriesDoc{
		Destinations: q.Destinations(), Locations: q.Locations(), Source: q.Source(),
		Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339), Points: nonNil(pts),
	}, nil
}
