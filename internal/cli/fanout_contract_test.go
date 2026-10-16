package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

// fanOutCommands are the commands that query once per customer name.
var fanOutCommands = [][]string{
	{"attacks", "list", "--since", "1h"},
	{"events"},
	{"metrics", "--type", "routed:bandwidthIn", "--since", "1h"},
	{"protected"},
	{"routed", "sessions"},
	{"routed", "health"},
	{"routed", "routes"},
}

// perName answers every request except the customer-name list with h.
func perName(h func(http.ResponseWriter)) func(http.ResponseWriter, *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/customer/names") {
			return false
		}
		h(w)
		return true
	}
}

// A name that fails still gives a document: every name in failures, empty
// rows, and the failures' exit code.
func TestFanOutFailedNamesGiveADocument(t *testing.T) {
	for _, args := range fanOutCommands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			api := newFakeAPI(t)
			api.intercept = perName(func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"title":"Forbidden","status":403}`))
			})
			r := runCLI(t, api.env(), append(args, "--customer", "example-a,example-b")...)
			var doc struct {
				Failures []struct{ Customer string } `json:"failures"`
			}
			if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
				t.Fatalf("no document (exit %d): %v\n%s", r.code, err, r.stderr)
			}
			if r.code != exitCode(apperr.Credentials) || len(doc.Failures) != 2 {
				t.Errorf("exit = %d, failures = %+v", r.code, doc.Failures)
			}
		})
	}
}

// A run cancelled during the fan-out exits 130 with no document.
func TestFanOutCancelledGivesNoDocument(t *testing.T) {
	for _, args := range fanOutCommands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			api := newFakeAPI(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api.intercept = perName(func(w http.ResponseWriter) {
				cancel()
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
			})
			env := api.env()
			var stdout, stderr strings.Builder
			env.Stdout, env.Stderr, env.Home = &stdout, &stderr, t.TempDir()
			code := Run(ctx, append(args, "--customer", "example-a,example-b"), env)
			if code != exitCode(apperr.Cancelled) || stdout.Len() != 0 {
				t.Errorf("exit = %d, stdout = %q", code, stdout.String())
			}
		})
	}
}

// Outcomes are data: the operation returns its document and no error, and
// the document's Outcome says what the CLI exits with.
func TestOutcomesAreDataNotErrors(t *testing.T) {
	api := newFakeAPI(t)
	api.intercept = perName(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"title":"Forbidden","status":403}`))
	})
	env := api.env()
	env.Home = t.TempDir()
	a := &app{env: env, section: "default"}
	d, err := a.ops().RoutedSessions(context.Background(), ops.RoutedSessionsInput{Customers: []string{"example-a"}})
	if err != nil {
		t.Fatalf("a failed name returned an error: %v", err)
	}
	if apperr.KindOf(d.Outcome()) != apperr.Credentials {
		t.Errorf("outcome = %v", d.Outcome())
	}
	if len(d.Failures) != 1 || d.Failures[0].Kind != apperr.Credentials {
		t.Errorf("failures = %+v", d.Failures)
	}
}

// Operations never stand in a default for a value a front could have given
// explicitly: an empty or zero value is refused, whichever front sent it.
// Defaults are the front's (the CLI's flag defaults).
func TestOperationsAssumeNoDefaults(t *testing.T) {
	api := newFakeAPI(t)
	env := api.env()
	env.Home = t.TempDir()
	r := (&app{env: env, section: "default"}).ops()
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"routed check, no expectation": func() error {
			_, err := r.RoutedCheck(ctx, ops.RoutedCheckInput{Prefix: "203.0.113.0/24"})
			return err
		},
		"routed check, waiting with no interval": func() error {
			_, err := r.RoutedCheck(ctx, ops.RoutedCheckInput{Prefix: "203.0.113.0/24", Expect: "present", Wait: time.Minute})
			return err
		},
		"metrics, no samples": func() error {
			_, err := r.Metrics(ctx, ops.MetricsInput{Types: []string{"routed:bandwidthIn"}})
			return err
		},
		"time series, no source": func() error {
			_, err := r.TimeSeries(ctx, ops.TimeSeriesInput{Destinations: []string{"203.0.113.1"}})
			return err
		},
		"export, no role": func() error {
			_, err := r.Export(ctx, ops.ExportInput{File: filepath.Join(t.TempDir(), "desired.json")})
			return err
		},
	} {
		if err := call(); apperr.KindOf(err) != apperr.Usage {
			t.Errorf("%s: err = %v, want a usage error", name, err)
		}
	}
}
