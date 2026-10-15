package ncfapi

import (
	"context"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// A caller's value that can't be one path segment is refused before
// anything is sent, by every V2 method that puts one in a path.
func TestCallerValuesArePathSegments(t *testing.T) {
	s, f := newV2(t)
	ctx := context.Background()
	now := time.Now()
	calls := map[string]func(bad string) error{
		"GetVersion":          func(b string) error { _, err := s.GetVersion(ctx, 101, b); return err },
		"Activate":            func(b string) error { return s.Activate(ctx, 101, b) },
		"GetRuleHit":          func(b string) error { _, err := s.GetRuleHit(ctx, b); return err },
		"RuleTimeSeries":      func(b string) error { _, err := s.RuleTimeSeries(ctx, b, now.Add(-time.Hour), now); return err },
		"GetManagedACL":       func(b string) error { _, err := s.GetManagedACL(ctx, b); return err },
		"ListManagedRuleHits": func(b string) error { _, err := s.ListManagedRuleHits(ctx, b); return err },
		"ManagedRuleTimeSeries/domain": func(b string) error {
			_, err := s.ManagedRuleTimeSeries(ctx, b, "r", now.Add(-time.Hour), now)
			return err
		},
		"ManagedRuleTimeSeries/rule": func(b string) error {
			_, err := s.ManagedRuleTimeSeries(ctx, "d", b, now.Add(-time.Hour), now)
			return err
		},
	}
	for method, call := range calls {
		for _, bad := range []string{"", ".", "..", "a/b"} {
			if err := call(bad); apperr.KindOf(err) != apperr.Usage {
				t.Errorf("%s(%q) = %v, want a usage error", method, bad, err)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Errorf("requests sent: %v", f.seen)
	}
}
