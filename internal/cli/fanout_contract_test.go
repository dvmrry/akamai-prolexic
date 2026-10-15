package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
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
			if r.code != int(apperr.Credentials) || len(doc.Failures) != 2 {
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
			if code != int(apperr.Cancelled) || stdout.Len() != 0 {
				t.Errorf("exit = %d, stdout = %q", code, stdout.String())
			}
		})
	}
}
