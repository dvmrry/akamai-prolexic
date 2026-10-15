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

func TestForCustomersReportsFailuresWithTheResult(t *testing.T) {
	res, err := ForCustomers(context.Background(), nil, fixedNames("example-a", "example-b"), nil,
		func(_ context.Context, name string) ([]string, error) {
			if name == "example-b" {
				return nil, apperr.New(apperr.Credentials, "no access")
			}
			return []string{name}, nil
		})
	if res == nil || apperr.KindOf(err) != apperr.Credentials {
		t.Fatalf("res = %+v, err = %v", res, err)
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
