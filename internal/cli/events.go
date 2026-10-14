package cli

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

// EventsDoc lists critical events and events across customer names.
type EventsDoc struct {
	output.Header
	Customers []string             `json:"customers" doc:"The customer names queried."`
	Start     string               `json:"start,omitempty" doc:"Window start, RFC 3339 UTC; set only when a window was asked for."`
	End       string               `json:"end,omitempty" doc:"Window end, RFC 3339 UTC; set only when a window was asked for."`
	Events    []analytics.EventRow `json:"events" doc:"Sorted by time, customer, kind."`
	Failures  []analytics.Failure  `json:"failures" doc:"Customer names whose query failed; either list failing fails the name."`
}

func (*EventsDoc) SchemaID() string { return "prolexic.events.v1" }

func (d *EventsDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tCUSTOMER\tKIND\tLOCATION\tSUMMARY")
	for _, e := range d.Events {
		var loc, summary string
		switch {
		case e.Critical != nil:
			loc, summary = e.Critical.Location, e.Critical.Summary
		case e.Event != nil:
			summary = e.Event.EventTitle
			if e.Event.EventInfo != nil {
				loc = e.Event.EventInfo.Location
			}
			summary = e.Event.EventType + ": " + summary
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", dash(e.Time), e.Customer, e.Kind, dash(loc), dash(summary))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

func runEvents(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	var customers stringList
	fs.Var(&customers, "customer", "customer name to query; repeatable or comma-separated (default: every in-use name)")
	criticalOnly := fs.Bool("critical-only", false, "only critical events")
	var win windowFlags
	win.register(fs, 0)
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	// The API has no time window for events: --since/--start/--end filter the
	// answer here, keeping events whose span overlaps the window.
	start, end, windowed, err := win.resolve(fs, a.env.Now())
	if err != nil {
		return nil, err
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}
	rows, failures, err := analytics.FanOut(ctx, names, func(ctx context.Context, name string) ([]analytics.EventRow, error) {
		crit, err := api.CriticalEvents(ctx, name)
		if err != nil || *criticalOnly {
			return crit, err
		}
		evs, err := api.Events(ctx, name)
		return append(crit, evs...), err
	})
	if ctx.Err() != nil {
		return nil, err
	}
	doc := &EventsDoc{Customers: names}
	if windowed {
		rows = slices.DeleteFunc(rows, func(r analytics.EventRow) bool { return !r.Overlaps(start, end) })
		doc.Start, doc.End = start.Format(time.RFC3339), end.Format(time.RFC3339)
	}
	slices.SortStableFunc(rows, func(x, y analytics.EventRow) int {
		return cmp.Or(cmp.Compare(x.At(), y.At()), cmp.Compare(x.Customer, y.Customer), cmp.Compare(x.Kind, y.Kind))
	})
	doc.Events, doc.Failures = nonNil(rows), nonNil(failures)
	return doc, err
}
