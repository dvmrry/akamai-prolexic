package analytics

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// A customer name that can't be one path segment is refused before anything
// is sent, by every method that puts it in a path.
func TestCustomerNameIsAPathSegment(t *testing.T) {
	sent := 0
	c := testAPI(t, func(http.ResponseWriter, *http.Request) { sent++ })
	ctx := context.Background()
	now := time.Now()
	calls := map[string]func(name string) error{
		"MetricTypes":    func(n string) error { _, err := c.MetricTypes(ctx, n); return err },
		"AttackReports":  func(n string) error { _, err := c.AttackReports(ctx, n, now.Add(-time.Hour), now); return err },
		"Attack":         func(n string) error { _, err := c.Attack(ctx, n, 1); return err },
		"Events":         func(n string) error { _, err := c.Events(ctx, n); return err },
		"CriticalEvents": func(n string) error { _, err := c.CriticalEvents(ctx, n); return err },
	}
	for method, call := range calls {
		for _, bad := range []string{"", ".", "..", "a/b"} {
			if err := call(bad); apperr.KindOf(err) != apperr.Usage {
				t.Errorf("%s(%q) = %v, want a usage error", method, bad, err)
			}
		}
	}
	if sent != 0 {
		t.Errorf("%d requests sent, want none", sent)
	}
}
