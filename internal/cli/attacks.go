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

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

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

// epoch renders UNIX seconds as RFC 3339 UTC; 0 (unset) as "-".
func epoch(e analytics.Epoch) string {
	sec := e.Unix()
	if sec <= 0 {
		return "-"
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func runAttacksList(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	var customers stringList
	fs.Var(&customers, "customer", "customer name to query; repeatable or comma-separated (default: every in-use name)")
	var win windowFlags
	win.register(fs, 24*time.Hour)
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	start, end, _, err := win.resolve(fs, a.env.Now())
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
	rows, failures, err := analytics.FanOut(ctx, names, func(ctx context.Context, name string) ([]analytics.Attack, error) {
		return api.AttackReports(ctx, name, start, end)
	})
	if ctx.Err() != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y analytics.Attack) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.StartTime, y.StartTime),
			cmp.Compare(x.AttackID, y.AttackID),
		)
	})
	return &AttacksDoc{
		Customers: names, Start: start.Format(time.RFC3339), End: end.Format(time.RFC3339),
		Attacks: nonNil(rows), Failures: nonNil(failures),
	}, err
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

func runAttacksShow(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	id := fs.Int64("id", 0, "attack id (required)")
	customer := fs.String("customer", "", "customer name the attack belongs to (required)")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	if *id <= 0 || *customer == "" {
		return nil, apperr.New(apperr.Usage, "--id and --customer are both required\n%s", flagUsage(fs))
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	rows, err := api.Attack(ctx, *customer, *id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, apperr.New(apperr.NotFound, "attack %d has no report rows for %s", *id, *customer)
	}
	slices.SortStableFunc(rows, func(x, y analytics.AttackRow) int {
		return cmp.Or(
			cmp.Compare(x.Location, y.Location),
			cmp.Compare(x.IP, y.IP),
			cmp.Compare(x.Netmask, y.Netmask),
			cmp.Compare(x.EventPeakID, y.EventPeakID),
		)
	})
	return &AttackDoc{Customer: *customer, AttackID: *id, Rows: rows}, nil
}
