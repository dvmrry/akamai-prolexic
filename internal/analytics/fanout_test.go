package analytics

import (
	"context"
	"errors"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

func fixedNames(names ...string) Resolver {
	return func(context.Context, *Client, []string) ([]string, error) { return names, nil }
}

// A failed name is data: it is in Failures, and the run itself succeeds.
func TestForCustomersReportsFailuresAsData(t *testing.T) {
	res, err := ForCustomers(context.Background(), nil, fixedNames("example-a", "example-b"), nil,
		func(_ context.Context, name string) ([]string, error) {
			if name == "example-b" {
				return nil, apperr.New(apperr.Credentials, "no access")
			}
			return []string{name}, nil
		})
	if res == nil || err != nil {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if ferr := FailuresError(res.Failures, len(res.Customers)); apperr.KindOf(ferr) != apperr.Credentials {
		t.Errorf("FailuresError = %v", ferr)
	}
	if len(res.Rows) != 1 || len(res.Failures) != 1 || res.Failures[0].Customer != "example-b" || len(res.Customers) != 2 {
		t.Errorf("res = %+v", res)
	}
}

func TestForCustomersListsAreNeverNil(t *testing.T) {
	res, err := ForCustomers(context.Background(), nil, fixedNames("example-a"), nil,
		func(context.Context, string) ([]string, error) { return nil, nil })
	if err != nil || res.Rows == nil || res.Failures == nil {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

// Cancellation after every query has answered still yields no Result.
func TestForCustomersCancelledGivesNoResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	res, err := ForCustomers(ctx, nil, fixedNames("example-a"), nil,
		func(context.Context, string) ([]string, error) {
			cancel()
			return []string{"row"}, nil
		})
	if res != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

func TestForCustomersResolveErrorGivesNoResult(t *testing.T) {
	failing := func(context.Context, *Client, []string) ([]string, error) {
		return nil, apperr.New(apperr.NotFound, "unknown customer name")
	}
	res, err := ForCustomers(context.Background(), nil, failing, []string{"x"},
		func(context.Context, string) ([]string, error) { t.Error("queried"); return nil, nil })
	if res != nil || apperr.KindOf(err) != apperr.NotFound {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

func TestFailuresErrorCountsDistinctNames(t *testing.T) {
	if FailuresError(nil, 3) != nil {
		t.Error("no failures is no error")
	}
	err := FailuresError([]Failure{
		{Customer: "example-a", Kind: apperr.Credentials},
		{Customer: "example-a", Kind: apperr.Upstream}, // the same name failing twice (sessions and routes)
	}, 2)
	if apperr.KindOf(err) != apperr.Upstream || err.Error() != "1 of 2 customer names failed: example-a" {
		t.Errorf("err = %v (%s)", err, apperr.KindOf(err))
	}
}

// A query that panics fails its own name; the process and the other names
// carry on.
func TestFanOutRecoversAPanickingQuery(t *testing.T) {
	rows, failures, _ := FanOut(context.Background(), []string{"example-a", "example-b"}, func(_ context.Context, name string) ([]string, error) {
		if name == "example-b" {
			panic("an answer no decoder expected")
		}
		return []string{name}, nil
	})
	if len(rows) != 1 || rows[0] != "example-a" || len(failures) != 1 || failures[0].Customer != "example-b" || failures[0].Kind != apperr.Bug {
		t.Errorf("rows %v, failures %+v", rows, failures)
	}
}
