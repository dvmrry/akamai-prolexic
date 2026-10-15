package cli

import (
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// The exit codes are a public contract: this pins every one.
func TestExitCodes(t *testing.T) {
	want := map[apperr.Kind]int{
		apperr.OK: 0, apperr.Bug: 1, apperr.Usage: 2, apperr.Credentials: 3, apperr.NotFound: 4,
		apperr.Upstream: 5, apperr.Validation: 6, apperr.Drift: 7, apperr.Conflict: 8, apperr.Cancelled: 130,
	}
	if len(exitCodes) != len(want) {
		t.Errorf("exitCodes has %d kinds, want %d", len(exitCodes), len(want))
	}
	for k, c := range want {
		if got := exitCode(k); got != c {
			t.Errorf("exitCode(%s) = %d, want %d", k, got, c)
		}
	}
	if got := exitCode("no-such-kind"); got != 1 {
		t.Errorf("an unknown kind exits %d, want 1 (bug)", got)
	}
}
