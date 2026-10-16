package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// AttacksDefaultSince is the window Attacks reads when none is given.
const AttacksDefaultSince = 24 * time.Hour

// AttacksInput lists attack reports.
type AttacksInput struct {
	Customers []string // customer names; empty means every in-use name
	Window    Window   // zero means the last AttacksDefaultSince
}

// AttacksDoc lists attack reports across customer names.
type AttacksDoc struct {
	output.Header
	Customers []string            `json:"customers" doc:"The customer names queried."`
	Start     string              `json:"start" doc:"Window start, RFC 3339 UTC."`
	End       string              `json:"end" doc:"Window end, RFC 3339 UTC."`
	Attacks   []analytics.Attack  `json:"attacks" doc:"Sorted by customer, startTime, attackId."`
	Failures  []analytics.Failure `json:"failures" doc:"Customer names whose query failed."`
}

func (*AttacksDoc) SchemaID() string { return "prolexic.attacks.v1" }

func (d *AttacksDoc) Outcome() error { return failuresOutcome(d.Failures, d.Customers) }

func (d *AttacksDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tATTACK\tSTART\tEND\tTYPES\tTARGETS")
	for _, a := range d.Attacks {
		var targets []string
		for _, t := range a.Destinations {
			targets = append(targets, fmt.Sprintf("%s/%d", t.IP, t.Netmask))
		}
		end := "ongoing"
		if a.EndTime > 0 {
			end = epoch(a.EndTime)
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", a.Customer, a.AttackID, epoch(a.StartTime), end,
			dash(strings.Join(a.EventTypes, ",")), dash(strings.Join(targets, ",")))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

// Attacks lists the attack reports in the window, per customer name; a name
// whose query failed is reported in the document, not as an error.
func (r *Runtime) Attacks(ctx context.Context, in AttacksInput) (*AttacksDoc, error) {
	start, end, _, err := in.Window.resolve(r.now(), AttacksDefaultSince)
	if err != nil {
		return nil, err
	}
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, in.Customers, func(ctx context.Context, name string) ([]analytics.Attack, error) {
		return api.AttackReports(ctx, name, start, end)
	})
	if res == nil {
		return nil, err
	}
	slices.SortStableFunc(res.Rows, func(x, y analytics.Attack) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.StartTime, y.StartTime),
			cmp.Compare(x.AttackID, y.AttackID),
		)
	})
	return &AttacksDoc{
		Customers: res.Customers, Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339),
		Attacks: res.Rows, Failures: res.Failures,
	}, nil
}

// AttackInput names one attack.
type AttackInput struct {
	Customer string // the customer name the attack belongs to; required
	ID       int64  // the attack id; required
}

// AttackDoc is one attack's detail report.
type AttackDoc struct {
	output.Header
	Customer string                `json:"customer" doc:"The customer name queried."`
	AttackID int64                 `json:"attackId"`
	Rows     []analytics.AttackRow `json:"rows" doc:"One row per location and target, sorted by location, ip, netmask, eventPeakId."`
}

func (*AttackDoc) SchemaID() string { return "prolexic.attack.v1" }

func (d *AttackDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LOCATION\tTARGET\tTYPE\tSTART\tEND\tPEAK BW\tPEAK PPS")
	for _, r := range d.Rows {
		end := "ongoing"
		if r.EndTime > 0 {
			end = epoch(r.EndTime)
		}
		fmt.Fprintf(tw, "%s\t%s/%d\t%s\t%s\t%s\t%d\t%d\n", r.Location, r.IP, r.Netmask, dash(r.AttackTypeName),
			epoch(r.StartTime), end, r.EventBw, r.EventPps)
	}
	return tw.Flush()
}

// Attack is one attack's detail report: one row per location and target.
func (r *Runtime) Attack(ctx context.Context, in AttackInput) (*AttackDoc, error) {
	switch {
	case in.ID <= 0:
		return nil, apperr.New(apperr.Usage, "the attack id must be positive")
	case in.Customer == "":
		return nil, apperr.New(apperr.Usage, "the attack's customer name is required")
	}
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	rows, err := api.Attack(ctx, in.Customer, in.ID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, apperr.New(apperr.NotFound, "attack %d has no report rows for %s", in.ID, in.Customer)
	}
	slices.SortStableFunc(rows, func(x, y analytics.AttackRow) int {
		return cmp.Or(
			cmp.Compare(x.Location, y.Location),
			cmp.Compare(x.IP, y.IP),
			cmp.Compare(x.Netmask, y.Netmask),
			cmp.Compare(x.EventPeakID, y.EventPeakID),
		)
	})
	return &AttackDoc{Customer: in.Customer, AttackID: in.ID, Rows: rows}, nil
}
