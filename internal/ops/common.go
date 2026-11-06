package ops

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
)

// failuresOutcome is the outcome of a document listing failed customer names.
func failuresOutcome(failures []analytics.Failure, customers []string) error {
	return analytics.FailuresError(failures, len(customers))
}

// writeFailures appends a fan-out's failures to a text rendering.
func writeFailures(w io.Writer, failures []analytics.Failure) error {
	for _, f := range failures {
		if _, err := fmt.Fprintf(w, "\nfailed: %s: %s", f.Customer, f.Message); err != nil {
			return err
		}
	}
	if len(failures) > 0 {
		_, err := fmt.Fprintln(w)
		return err
	}
	return nil
}

// rowKey is a row's JSON encoding: the last sort key, so rows that tie on
// every named key still come out in one order whatever order the API sent.
func rowKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// nonNil keeps empty lists as [] rather than null in JSON: the schemas
// declare arrays.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// epoch renders UNIX seconds as RFC 3339 UTC; 0 (unset) as "-".
func epoch(e analytics.Epoch) string {
	sec := e.Unix()
	if sec <= 0 {
		return "-"
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}
