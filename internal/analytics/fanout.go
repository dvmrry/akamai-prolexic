package analytics

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Failure is a customer name whose query failed. Commands report failures in
// their document instead of dropping the name.
type Failure struct {
	Customer string      `json:"customer"`
	Kind     apperr.Kind `json:"kind" enum:"bug,usage,credentials,not_found,upstream,validation,drift,conflict,cancelled"`
	Message  string      `json:"message"`
}

// fanOutLimit bounds concurrent queries per command.
const fanOutLimit = 4

// FanOut runs query once per customer name, concurrently, and concatenates
// the rows in the names' order. A failed name becomes a Failure; if any
// failed, the error says how many, with the failures' common kind (or
// Upstream when they differ). Rows from the names that worked are returned
// either way. A cancelled context returns the context's error.
func FanOut[T any](ctx context.Context, customers []string, query func(context.Context, string) ([]T, error)) ([]T, []Failure, error) {
	type result struct {
		rows []T
		err  error
	}
	results := make([]result, len(customers))
	sem := make(chan struct{}, fanOutLimit)
	var wg sync.WaitGroup
	for i, name := range customers {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			// A panic here (an answer no decoder expected) would end the
			// process, past any recover in the caller's goroutine: it
			// becomes this name's failure instead.
			defer func() {
				if p := recover(); p != nil {
					results[i] = result{err: apperr.New(apperr.Bug, "query for %s failed unexpectedly: %v", name, p)}
				}
			}()
			rows, err := query(ctx, name)
			results[i] = result{rows, err}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	var rows []T
	var failures []Failure
	for i, r := range results {
		if r.err != nil {
			failures = append(failures, Failure{Customer: customers[i], Kind: apperr.KindOf(r.err), Message: r.err.Error()})
			continue
		}
		rows = append(rows, r.rows...)
	}
	return rows, failures, FailuresError(failures, len(customers))
}

// FailuresError summarises failed customer names as one error: nil when
// there are none, otherwise the failures' common kind (Upstream when they
// differ) and the distinct names that failed, out of total.
func FailuresError(failures []Failure, total int) error {
	if len(failures) == 0 {
		return nil
	}
	kind := failures[0].Kind
	var names []string
	for _, f := range failures {
		if f.Kind != kind {
			kind = apperr.Upstream
		}
		if !slices.Contains(names, f.Customer) {
			names = append(names, f.Customer)
		}
	}
	return apperr.New(kind, "%d of %d customer names failed: %s", len(names), total, strings.Join(names, ", "))
}

// ResolveCustomers returns the names to query: the explicit ones if any
// (deduplicated, in the given order), otherwise every in-use name of the
// account, sorted.
func ResolveCustomers(ctx context.Context, c *Client, explicit []string) ([]string, error) {
	all, err := c.CustomerNames(ctx)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindOf(err), err, "resolve customer names")
	}
	if len(explicit) > 0 {
		// Check explicit names against the account: several endpoints
		// answer an unknown name like an empty window (404), which would
		// make a typo look like "no attacks".
		known := map[string]bool{}
		for _, n := range all {
			known[n.Name] = true
		}
		var out []string
		for _, n := range explicit {
			if n == "" || slices.Contains(out, n) {
				continue
			}
			if !known[n] {
				return nil, apperr.New(apperr.NotFound, "unknown customer name %q; prolexic customers lists the account's names", n)
			}
			out = append(out, n)
		}
		return out, nil
	}
	var out []string
	for _, n := range all {
		if n.InUse && !slices.Contains(out, n.Name) {
			out = append(out, n.Name)
		}
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil, apperr.New(apperr.NotFound, "the account has no customer names in use")
	}
	return out, nil
}

// Resolver picks the customer names a query covers from the explicit ones
// given: ResolveCustomers (every in-use name by default) or AllCustomers.
type Resolver func(ctx context.Context, c *Client, explicit []string) ([]string, error)

// Result is a query run once per customer name. Its lists are never nil.
type Result[T any] struct {
	Customers []string  // the names queried
	Rows      []T       // from the names that answered, in the names' order
	Failures  []Failure // the names that failed
}

// ForCustomers resolves the customer names and runs query once per name.
//   - A failed name is data, not an error: it is reported in Failures, and
//     FailuresError summarises them for a front that wants one error.
//   - Anything else that stops the run (resolving the names, or a cancelled
//     context) returns no Result, only the error. A cancelled run never yields
//     a partial Result, even when the cancellation came after every query.
func ForCustomers[T any](ctx context.Context, c *Client, resolve Resolver, explicit []string, query func(context.Context, string) ([]T, error)) (*Result[T], error) {
	names, err := resolve(ctx, c, explicit)
	if err != nil {
		return nil, err
	}
	rows, failures, _ := FanOut(ctx, names, query) // partial failures are in failures
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr
	}
	if rows == nil {
		rows = []T{}
	}
	if failures == nil {
		failures = []Failure{}
	}
	return &Result[T]{Customers: names, Rows: rows, Failures: failures}, nil
}
