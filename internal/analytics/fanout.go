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
	Customer string `json:"customer"`
	Code     int    `json:"code" doc:"The exit code this failure alone would have."`
	Kind     string `json:"kind"`
	Message  string `json:"message"`
}

// fanOutLimit bounds concurrent queries per command.
const fanOutLimit = 4

// FanOut runs query once per customer name, concurrently, and concatenates
// the rows in the names' order. A failed name becomes a Failure; if any
// failed, the error says how many, with the failures' common exit code (or
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
			code := apperr.CodeOf(r.err)
			failures = append(failures, Failure{Customer: customers[i], Code: int(code), Kind: code.Kind(), Message: r.err.Error()})
			continue
		}
		rows = append(rows, r.rows...)
	}
	if len(failures) == 0 {
		return rows, nil, nil
	}
	code := apperr.Code(failures[0].Code)
	for _, f := range failures[1:] {
		if apperr.Code(f.Code) != code {
			code = apperr.Upstream
		}
	}
	names := make([]string, len(failures))
	for i, f := range failures {
		names[i] = f.Customer
	}
	return rows, failures, apperr.New(code, "%d of %d customer names failed: %s", len(failures), len(customers), strings.Join(names, ", "))
}

// ResolveCustomers returns the names to query: the explicit ones if any
// (deduplicated, in the given order), otherwise every in-use name of the
// account, sorted.
func ResolveCustomers(ctx context.Context, c *Client, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		var out []string
		for _, n := range explicit {
			if n != "" && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		return out, nil
	}
	all, err := c.CustomerNames(ctx)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeOf(err), err, "resolve customer names")
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
