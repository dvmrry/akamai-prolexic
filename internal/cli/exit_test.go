package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

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

// failFirst fails its first write, then records the rest: stderr that broke
// once, as a pipe can.
type failFirst struct {
	failed bool
	buf    bytes.Buffer
}

func (f *failFirst) Write(p []byte) (int, error) {
	if !f.failed {
		f.failed = true
		return 0, errors.New("broken pipe")
	}
	return f.buf.Write(p)
}

// When the error document can't be written, the plain fallback line is still
// escaped: an error can carry upstream text with terminal escapes.
func TestFailFallbackIsEscaped(t *testing.T) {
	w := &failFirst{}
	a := &app{env: Env{Stderr: w, Now: time.Now}}
	if code := a.fail(apperr.New(apperr.Upstream, "upstream said: \x1b]0;pwned\x07 bad")); code != 5 {
		t.Errorf("code = %d", code)
	}
	if got := w.buf.String(); strings.ContainsAny(got, "\x1b\x07") || !strings.Contains(got, "upstream said") {
		t.Errorf("fallback = %q", got)
	}
}
