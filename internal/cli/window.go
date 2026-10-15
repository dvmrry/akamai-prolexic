package cli

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// windowFlags are the time-window flags shared by attacks and events:
// --since DURATION, or --start/--end (RFC 3339). They are mutually exclusive.
type windowFlags struct {
	since time.Duration
	start string
	end   string

	flags *pflag.FlagSet // the command's flags, to tell an explicit --since from its default
}

func (w *windowFlags) register(cmd *cobra.Command, defaultSince time.Duration) {
	fs := cmd.Flags()
	w.flags = fs
	fs.DurationVar(&w.since, "since", defaultSince, "window ending now, e.g. 24h; exclusive with --start/--end")
	fs.StringVar(&w.start, "start", "", "window start, RFC 3339 (e.g. 2026-01-01T00:00:00Z)")
	fs.StringVar(&w.end, "end", "", "window end, RFC 3339 (default: now)")
}

// resolve returns the window, UTC. given is false when the user set no flag
// and defaultSince is 0: the caller then applies no window at all.
func (w *windowFlags) resolve(now time.Time) (start, end time.Time, given bool, err error) {
	sinceSet := w.flags.Changed("since")
	if sinceSet && (w.start != "" || w.end != "") {
		return start, end, false, apperr.New(apperr.Usage, "--since can't be combined with --start/--end")
	}
	now = now.UTC()
	switch {
	case w.start != "" || w.end != "":
		if w.start == "" {
			return start, end, false, apperr.New(apperr.Usage, "--end needs --start")
		}
		if start, err = time.Parse(time.RFC3339, w.start); err != nil {
			return start, end, false, apperr.New(apperr.Usage, "--start: want RFC 3339, got %q", w.start)
		}
		end = now
		if w.end != "" {
			if end, err = time.Parse(time.RFC3339, w.end); err != nil {
				return start, end, false, apperr.New(apperr.Usage, "--end: want RFC 3339, got %q", w.end)
			}
		}
	case w.since > 0:
		start, end = now.Add(-w.since), now
	case w.since < 0 || sinceSet:
		return start, end, false, apperr.New(apperr.Usage, "--since must be positive")
	default:
		return start, end, false, nil
	}
	if !start.Before(end) {
		return start, end, false, apperr.New(apperr.Usage, "the window start (%s) must be before its end (%s)", start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	}
	return start.UTC(), end.UTC(), true, nil
}
