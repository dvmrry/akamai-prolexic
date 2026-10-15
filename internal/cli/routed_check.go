package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// RoutedCheckDoc is the result of a prefix propagation check.
type RoutedCheckDoc struct {
	output.Header
	Customers []string                   `json:"customers" doc:"The customer names queried."`
	Prefix    string                     `json:"prefix" doc:"The normalised prefix checked."`
	Expect    string                     `json:"expect" doc:"present: every expected session carries the prefix; absent: none does."`
	Sites     []string                   `json:"sites" doc:"The --site filter; empty means every data center."`
	Satisfied bool                       `json:"satisfied" doc:"Whether the expectation held on the last attempt, with no failures and at least one expected session."`
	Attempts  int                        `json:"attempts" doc:"How many times sessions and routes were fetched."`
	Sessions  []analytics.SessionCheck   `json:"sessions" doc:"The expected sessions, sorted by customer, dataCenter, routerName, peer."`
	Skipped   []analytics.SkippedSession `json:"skipped" doc:"Sessions with no BGP peer of the prefix's address family; not expected."`
	Failures  []analytics.Failure        `json:"failures" doc:"Customer names whose query failed on the last attempt."`
}

func (*RoutedCheckDoc) SchemaID() string { return "prolexic.routed-check.v1" }

func (d *RoutedCheckDoc) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "prefix %s expected %s: ", d.Prefix, d.Expect)
	if d.Satisfied {
		fmt.Fprintf(w, "satisfied (attempts: %d)\n", d.Attempts)
	} else {
		fmt.Fprintf(w, "NOT satisfied (attempts: %d)\n", d.Attempts)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tDATA CENTER\tROUTER\tPEER\tCARRIED")
	for _, s := range d.Sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\n", s.Customer, s.DataCenter, s.RouterName, s.Peer, s.Carried)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, s := range d.Skipped {
		fmt.Fprintf(w, "skipped (no peer of this family): %s %s %s\n", s.Customer, s.DataCenter, s.RouterName)
	}
	return writeFailures(w, d.Failures)
}

func newRoutedCheckCmd(a *app) *cobra.Command {
	var customers, sites []string
	var prefix, expect string
	var wait, interval time.Duration
	cmd := &cobra.Command{
		Use:     "check",
		Short:   "check a prefix has propagated (or gone) on every session",
		Long:    "Checks, per BGP session, that the prefix is announced to Akamai (--expect present) or not (--expect absent). With --wait it keeps polling every --interval until satisfied or the time runs out.",
		Example: "  prolexic routed check --prefix 198.51.100.0/24 --wait 10m",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return routedCheck(ctx, a, customers, sites, prefix, expect, wait, interval)
		}),
	}
	customerFlag(cmd, &customers)
	f := cmd.Flags()
	listVar(f, &sites, "site", "only sessions in this data center; repeatable or comma-separated")
	f.StringVar(&prefix, "prefix", "", "the prefix to check (required; a bare address means /32 or /128)")
	f.StringVar(&expect, "expect", "present", "present: every expected session carries the prefix; absent: none does")
	f.DurationVar(&wait, "wait", 0, "keep checking until satisfied or this long has passed (0: check once)")
	f.DurationVar(&interval, "interval", 30*time.Second, "time between checks while waiting")
	_ = cmd.MarkFlagRequired("prefix")
	return cmd
}

func routedCheck(ctx context.Context, a *app, customers, sites []string, prefixFlag, expectFlag string, wait, interval time.Duration) (output.Document, error) {
	prefix, err := analytics.ParsePrefix(prefixFlag)
	if err != nil {
		return nil, err
	}
	expect, err := analytics.ParseExpect(expectFlag)
	if err != nil {
		return nil, err
	}
	if wait < 0 || (wait > 0 && interval <= 0) {
		return nil, apperr.New(apperr.Usage, "--wait must be >= 0 and --interval > 0")
	}
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}

	deadline := a.env.Now().Add(wait)
	doc := &RoutedCheckDoc{Customers: names, Prefix: prefix.String(), Expect: string(expect), Sites: nonNil(sites)}
	var ferr error
	for {
		doc.Attempts++
		sessions, sfail, serr := analytics.FanOut(ctx, names, api.BGPSessions)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		routes, rfail, rerr := analytics.FanOut(ctx, names, api.Routes)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		doc.Failures = nonNil(append(sfail, rfail...))
		ferr = serr
		if ferr == nil {
			ferr = rerr
		}
		res := analytics.EvaluateCheck(sessions, routes, prefix, expect, sites)
		doc.Sessions, doc.Skipped = nonNil(res.Sessions), nonNil(res.Skipped)
		doc.Satisfied = res.Satisfied() && ferr == nil
		if len(res.Sessions) == 0 && ferr == nil {
			return doc, apperr.New(apperr.NotFound, "no session to check for %s: %d skipped (no peer of that family), the rest filtered out by --site/--customer", prefix, len(res.Skipped))
		}
		if doc.Satisfied {
			return doc, nil
		}
		remaining := deadline.Sub(a.env.Now())
		if remaining <= 0 {
			if ferr != nil {
				return doc, ferr
			}
			return doc, apperr.New(apperr.Drift, "%d of %d sessions do not match --expect %s for %s", res.Off, len(res.Sessions), expect, prefix)
		}
		if err := a.env.Sleep(ctx, min(interval, remaining)); err != nil {
			return nil, err
		}
	}
}
