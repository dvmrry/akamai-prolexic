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

func newAttacksListCmd(a *app) *cobra.Command {
	var customers []string
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "list",
		Short: "attacks in a time window per customer name",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return attacksList(ctx, a, customers, win)
		}),
	}
	customerFlag(cmd, &customers)
	win.register(cmd, 24*time.Hour)
	return cmd
}

func attacksList(ctx context.Context, a *app, customers []string, win windowFlags) (output.Document, error) {
	start, end, _, err := win.resolve(a.env.Now())
	if err != nil {
		return nil, err
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, customers, func(ctx context.Context, name string) ([]analytics.Attack, error) {
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

func newAttacksShowCmd(a *app) *cobra.Command {
	var id int64
	var customer string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one attack's detail report",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return attacksShow(ctx, a, id, customer)
		}),
	}
	f := cmd.Flags()
	f.Int64Var(&id, "id", 0, "attack id (required)")
	f.StringVar(&customer, "customer", "", "customer name the attack belongs to (required)")
	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("customer")
	return cmd
}

func attacksShow(ctx context.Context, a *app, id int64, customer string) (output.Document, error) {
	if id <= 0 {
		return nil, apperr.New(apperr.Usage, "--id must be a positive attack id")
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	rows, err := api.Attack(ctx, customer, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, apperr.New(apperr.NotFound, "attack %d has no report rows for %s", id, customer)
	}
	slices.SortStableFunc(rows, func(x, y analytics.AttackRow) int {
		return cmp.Or(
			cmp.Compare(x.Location, y.Location),
			cmp.Compare(x.IP, y.IP),
			cmp.Compare(x.Netmask, y.Netmask),
			cmp.Compare(x.EventPeakID, y.EventPeakID),
		)
	})
	return &AttackDoc{Customer: customer, AttackID: id, Rows: rows}, nil
}
