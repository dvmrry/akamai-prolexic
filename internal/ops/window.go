package ops

import (
	"cmp"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Window is a time window: Since back from now, or Start and End in RFC 3339
// (End defaults to now). The zero Window takes the operation's default,
// which for some operations is no window at all.
type Window struct {
	Since time.Duration
	Start string
	End   string
}

// resolve returns the window in UTC. given is false when w is zero and def
// is 0: the operation then applies no window.
func (w Window) resolve(now time.Time, def time.Duration) (start, end time.Time, given bool, err error) {
	switch {
	case w.Since < 0:
		return start, end, false, apperr.New(apperr.Usage, "since must be positive")
	case w.Since > 0 && (w.Start != "" || w.End != ""):
		return start, end, false, apperr.New(apperr.Usage, "since can't be combined with start or end")
	}
	now = now.UTC()
	if w.Start != "" || w.End != "" {
		if w.Start == "" {
			return start, end, false, apperr.New(apperr.Usage, "an end needs a start")
		}
		if start, err = time.Parse(time.RFC3339, w.Start); err != nil {
			return start, end, false, apperr.New(apperr.Usage, "start: want RFC 3339, got %q", w.Start)
		}
		end = now
		if w.End != "" {
			if end, err = time.Parse(time.RFC3339, w.End); err != nil {
				return start, end, false, apperr.New(apperr.Usage, "end: want RFC 3339, got %q", w.End)
			}
		}
	} else {
		since := cmp.Or(w.Since, def)
		if since == 0 {
			return start, end, false, nil
		}
		start, end = now.Add(-since), now
	}
	if !start.Before(end) {
		return start, end, false, apperr.New(apperr.Usage, "the window start (%s) must be before its end (%s)", start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	}
	return start.UTC(), end.UTC(), true, nil
}
