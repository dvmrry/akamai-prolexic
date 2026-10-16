package cli

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

// windowFlags are the time-window flags the windowed commands share:
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

// window is the flags as an ops.Window. --since goes in only when given, so
// the operation's default (the one register showed) applies otherwise. The
// combinations are checked here too, for messages that name the flags.
func (w *windowFlags) window() (ops.Window, error) {
	sinceSet := w.flags.Changed("since")
	switch {
	case sinceSet && (w.start != "" || w.end != ""):
		return ops.Window{}, apperr.New(apperr.Usage, "--since can't be combined with --start/--end")
	case sinceSet && w.since <= 0:
		return ops.Window{}, apperr.New(apperr.Usage, "--since must be positive")
	case w.end != "" && w.start == "":
		return ops.Window{}, apperr.New(apperr.Usage, "--end needs --start")
	}
	win := ops.Window{Start: w.start, End: w.end}
	if sinceSet {
		win.Since = w.since
	}
	return win, nil
}
