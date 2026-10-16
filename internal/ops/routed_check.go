package ops

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// DefaultCheckInterval is the usual time between checks while RoutedCheck
// waits: fronts offer it as the default; RoutedCheck never assumes it.
const DefaultCheckInterval = 30 * time.Second

// The limits on a waiting RoutedCheck: one call polls the API at most every
// MinCheckInterval, for at most MaxCheckWait.
const (
	MinCheckInterval = 5 * time.Second
	MaxCheckWait     = time.Hour
)

// RoutedCheckInput asks whether a prefix has propagated to, or gone from,
// every BGP session.
type RoutedCheckInput struct {
	Customers []string      // customer names; empty means every in-use name
	Sites     []string      // only sessions in these data centers; empty means all
	Prefix    string        // required; a bare address means /32 or /128
	Expect    string        // present or absent; required
	Wait      time.Duration // keep checking until satisfied or this long has passed; 0 checks once
	Interval  time.Duration // time between checks while waiting; must be positive when Wait is
}

// RoutedCheckDoc is the result of a prefix propagation check.
type RoutedCheckDoc struct {
	output.Header
	Customers []string                   `json:"customers" doc:"The customer names queried."`
	Prefix    string                     `json:"prefix" doc:"The normalised prefix checked."`
	Expect    string                     `json:"expect" doc:"present: every expected session carries the prefix; absent: none does."`
	Sites     []string                   `json:"sites" doc:"The data-center filter; empty means every data center."`
	Satisfied bool                       `json:"satisfied" doc:"Whether the expectation held on the last attempt, with no failures and at least one expected session."`
	Attempts  int                        `json:"attempts" doc:"How many times sessions and routes were fetched."`
	Sessions  []analytics.SessionCheck   `json:"sessions" doc:"The expected sessions, sorted by customer, dataCenter, routerName, peer."`
	Skipped   []analytics.SkippedSession `json:"skipped" doc:"Sessions with no BGP peer of the prefix's address family; not expected."`
	Failures  []analytics.Failure        `json:"failures" doc:"Customer names whose query failed on the last attempt."`

	sessionFailures int // Failures[:sessionFailures] came from the sessions query: they decide the outcome first
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

// RoutedCheck checks, per BGP session, that in.Prefix is announced to Akamai
// (expect present) or not (expect absent). With a wait it polls every
// interval until satisfied or the time runs out, reporting each attempt as
// progress. The document's Outcome says how the last attempt ended.
func (r *Runtime) RoutedCheck(ctx context.Context, in RoutedCheckInput) (*RoutedCheckDoc, error) {
	prefix, err := analytics.ParsePrefix(in.Prefix)
	if err != nil {
		return nil, err
	}
	expect, err := analytics.ParseExpect(in.Expect)
	if err != nil {
		return nil, err
	}
	switch {
	case in.Wait < 0 || in.Wait > MaxCheckWait:
		return nil, apperr.New(apperr.Usage, "the wait must be between 0 and %s", MaxCheckWait)
	case in.Wait > 0 && in.Interval < MinCheckInterval:
		// Each attempt queries every customer name twice: a tight interval
		// would hammer the API for the whole wait.
		return nil, apperr.New(apperr.Usage, "the interval must be at least %s when waiting", MinCheckInterval)
	}
	interval := in.Interval
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, in.Customers)
	if err != nil {
		return nil, err
	}

	deadline := r.now().Add(in.Wait)
	doc := &RoutedCheckDoc{Customers: names, Prefix: prefix.String(), Expect: string(expect), Sites: nonNil(in.Sites)}
	for {
		doc.Attempts++
		sessions, sfail, _ := analytics.FanOut(ctx, names, api.BGPSessions)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		routes, rfail, _ := analytics.FanOut(ctx, names, api.Routes)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		doc.Failures = nonNil(append(sfail, rfail...))
		doc.sessionFailures = len(sfail)
		res := analytics.EvaluateCheck(sessions, routes, prefix, expect, in.Sites)
		doc.Sessions, doc.Skipped = nonNil(res.Sessions), nonNil(res.Skipped)
		doc.Satisfied = res.Satisfied() && len(doc.Failures) == 0
		// Stop when satisfied, when there is nothing to check (waiting won't
		// change that), or at the deadline. Outcome says which.
		if doc.Satisfied || (len(res.Sessions) == 0 && len(doc.Failures) == 0) {
			return doc, nil
		}
		remaining := deadline.Sub(r.now())
		if remaining <= 0 {
			return doc, nil
		}
		next := min(interval, remaining)
		r.progress(fmt.Sprintf("attempt %d: %d of %d sessions match the expectation (%s), %d failed names; checking again in %s (%s left)",
			doc.Attempts, len(res.Sessions)-res.Off, len(res.Sessions), expect, failedNames(doc.Failures), next, remaining.Round(time.Second)))
		if err := r.sleep(ctx, next); err != nil {
			return nil, err
		}
	}
}

// Outcome is how the last attempt ended: failed names, nothing to check, or
// sessions that don't match the expectation.
func (d *RoutedCheckDoc) Outcome() error {
	// The sessions query's failures come first, then the routes query's: a name
	// failing both is reported with its sessions failure.
	n := min(d.sessionFailures, len(d.Failures))
	if err := failuresOutcome(d.Failures[:n], d.Customers); err != nil {
		return err
	}
	if err := failuresOutcome(d.Failures[n:], d.Customers); err != nil {
		return err
	}
	if len(d.Sessions) == 0 {
		return apperr.New(apperr.NotFound, "no session to check for %s: %d skipped (no peer of that family), the rest filtered out by the site or customer filter", d.Prefix, len(d.Skipped))
	}
	if d.Satisfied {
		return nil
	}
	off := 0
	for _, s := range d.Sessions {
		if s.Carried != (d.Expect == string(analytics.ExpectPresent)) {
			off++
		}
	}
	return apperr.New(apperr.Drift, "%d of %d sessions do not match the expectation (%s) for %s", off, len(d.Sessions), d.Expect, d.Prefix)
}

// failedNames counts the distinct customer names in failures: a name can fail
// both the sessions and the routes query.
func failedNames(failures []analytics.Failure) int {
	seen := map[string]bool{}
	for _, f := range failures {
		seen[f.Customer] = true
	}
	return len(seen)
}
