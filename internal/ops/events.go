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

func (d *EventsDoc) Outcome() error { return failuresOutcome(d.Failures, d.Customers) }

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

// EventsInput lists critical events and events.
type EventsInput struct {
	Customers    []string // customer names; empty means every in-use name
	CriticalOnly bool     // only critical events
	Window       Window   // keeps events whose span overlaps it; zero means every event
}

// Events lists critical events and events per customer name. The API has no
// time window for events: the window filters the answer here, keeping events
// whose span overlaps it. A name whose query failed is reported in the
// document, not as an error.
func (r *Runtime) Events(ctx context.Context, in EventsInput) (*EventsDoc, error) {
	start, end, windowed, err := in.Window.resolve(r.now(), 0)
	if err != nil {
		return nil, err
	}
	api, err := r.analyticsFor(in.Customers)
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, in.Customers, func(ctx context.Context, name string) ([]analytics.EventRow, error) {
		crit, err := api.CriticalEvents(ctx, name)
		if err != nil || in.CriticalOnly {
			return crit, err
		}
		evs, err := api.Events(ctx, name)
		return append(crit, evs...), err
	})
	if res == nil {
		return nil, err
	}
	doc := &EventsDoc{Customers: res.Customers}
	if windowed {
		res.Rows = slices.DeleteFunc(res.Rows, func(r analytics.EventRow) bool { return !r.Overlaps(start, end) })
		doc.Start, doc.End = start.Format(time.RFC3339), end.Format(time.RFC3339)
	}
	slices.SortStableFunc(res.Rows, func(x, y analytics.EventRow) int {
		return cmp.Or(cmp.Compare(x.At(), y.At()), cmp.Compare(x.Customer, y.Customer), cmp.Compare(x.Kind, y.Kind), cmp.Compare(rowKey(x), rowKey(y)))
	})
	doc.Events, doc.Failures = res.Rows, res.Failures
	return doc, nil
}
