package mcpfront

import (
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

// Argument types follow two rules:
//   - A value with a default is a pointer, so a value left out (the default,
//     from the ops constant the CLI also uses) differs from one given
//     explicitly, which the operation checks as given: an empty expectation
//     is an error, not "present".
//   - Durations are strings in Go syntax (90s, 10m, 24h).

// customersArg is the customer names a fan-out tool queries.
type customersArg struct {
	Customers []string `json:"customers,omitempty" doc:"Customer names to query; default every in-use name (the customers tool lists them)."`
}

// windowArg is a time window: since, or start and end.
type windowArg struct {
	Since string `json:"since,omitempty" doc:"How far back from now, as a duration such as 24h or 90m; exclusive with start and end. Default: the tool's own window."`
	Start string `json:"start,omitempty" doc:"Window start, RFC 3339, e.g. 2026-01-01T00:00:00Z."`
	End   string `json:"end,omitempty" doc:"Window end, RFC 3339; default now."`
}

// window is the argument as an ops.Window: since only when given, so the
// operation's default applies otherwise.
func (w windowArg) window() (ops.Window, error) {
	win := ops.Window{Start: w.Start, End: w.End}
	if w.Since != "" {
		d, err := duration("since", w.Since)
		if err != nil {
			return win, err
		}
		if d <= 0 {
			return win, apperr.New(apperr.Usage, "since must be positive")
		}
		win.Since = d
	}
	return win, nil
}

// duration parses a duration argument.
func duration(name, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, apperr.New(apperr.Usage, "%s: want a duration such as 90s, 10m or 24h, got %q", name, s)
	}
	return d, nil
}

// orDefault is *p, or def when the argument was left out.
func orDefault[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}
