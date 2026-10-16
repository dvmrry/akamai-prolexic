package ops

import (
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

func TestWindowResolve(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.FixedZone("x", 3600))
	utc := now.UTC()
	for name, tc := range map[string]struct {
		w          Window
		def        time.Duration
		start, end time.Time
		given      bool
		err        string
	}{
		"zero takes the default":   {Window{}, time.Hour, utc.Add(-time.Hour), utc, true, ""},
		"zero with no default":     {Window{}, 0, time.Time{}, time.Time{}, false, ""},
		"since overrides":          {Window{Since: 2 * time.Hour}, time.Hour, utc.Add(-2 * time.Hour), utc, true, ""},
		"start, end defaults now":  {Window{Start: "2026-10-16T08:00:00Z"}, time.Hour, time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC), utc, true, ""},
		"start equal to end":       {Window{Start: "2026-10-16T08:00:00Z", End: "2026-10-16T09:00:00+01:00"}, 0, time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC), time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC), false, "before its end"},
		"negative since":           {Window{Since: -time.Hour}, 0, time.Time{}, time.Time{}, false, "positive"},
		"since with start":         {Window{Since: time.Hour, Start: "2026-10-16T08:00:00Z"}, 0, time.Time{}, time.Time{}, false, "combined"},
		"end without start":        {Window{End: "2026-10-16T08:00:00Z"}, 0, time.Time{}, time.Time{}, false, "needs a start"},
		"bad start":                {Window{Start: "yesterday"}, 0, time.Time{}, time.Time{}, false, "RFC 3339"},
		"start after now (no end)": {Window{Start: "2027-01-01T00:00:00Z"}, 0, time.Time{}, time.Time{}, false, "before its end"},
	} {
		start, end, given, err := tc.w.resolve(now, tc.def)
		if tc.err != "" {
			if apperr.KindOf(err) != apperr.Usage || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v", name, err)
			}
			continue
		}
		if err != nil || !start.Equal(tc.start) || !end.Equal(tc.end) || given != tc.given || start.Location() != time.UTC {
			t.Errorf("%s: %v %v %v %v", name, start, end, given, err)
		}
	}
}
