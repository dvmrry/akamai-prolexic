package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newValidateCmd(a *app) *cobra.Command {
	var in ops.ValidateInput
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "offline checks of the desired file: no credentials, no network",
		Args:  cobra.NoArgs,
		RunE: a.run(func(context.Context, []string) (output.Document, error) {
			return output.Doc(a.ops().Validate(in))
		}),
	}
	fileFlag(cmd, &in.File)
	return cmd
}

func newFmtCmd(a *app) *cobra.Command {
	var in ops.FmtInput
	cmd := &cobra.Command{
		Use:   "fmt",
		Short: "rewrite the desired file in canonical form, or --check it (offline)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(context.Context, []string) (output.Document, error) {
			return output.Doc(a.ops().Fmt(in))
		}),
	}
	fileFlag(cmd, &in.File)
	cmd.Flags().BoolVar(&in.Check, "check", false, "fail if the file isn't canonical; write nothing")
	return cmd
}

func newAddCmd(a *app) *cobra.Command {
	var in ops.AddInput
	cmd := &cobra.Command{
		Use:     "add --file F <alias> <entry>... --ticket T --reason R [--expires YYYY-MM-DD]",
		Short:   "add entries to an alias in the desired file (offline)",
		Long:    "Adds entries, with ticket, reason and date metadata, to one alias of the desired file and rewrites it in canonical form. Offline validation runs first; on any error, or a warning about an added entry, nothing is written.",
		Example: "  prolexic add --file desired.json block-v4 198.51.100.7 --ticket SEC-123 --reason scanner",
		Args:    cobra.MinimumNArgs(2),
		RunE: a.run(func(_ context.Context, args []string) (output.Document, error) {
			if in.Expires != "" {
				if _, err := ncf.ParseDate(in.Expires); err != nil {
					return nil, apperr.New(apperr.Usage, "--expires %q is not YYYY-MM-DD", in.Expires)
				}
			}
			in.Alias, in.Entries = args[0], args[1:]
			return output.Doc(a.ops().Add(in))
		}),
	}
	f := cmd.Flags()
	f.StringVar(&in.File, "file", "", "the desired file (required)")
	f.StringVar(&in.Ticket, "ticket", "", "the ticket authorising the change (required)")
	f.StringVar(&in.Reason, "reason", "", "why the entries are added (required)")
	f.StringVar(&in.Expires, "expires", "", "YYYY-MM-DD after which the entries are flagged as expired")
	for _, name := range []string{"file", "ticket", "reason"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newRemoveCmd(a *app) *cobra.Command {
	var in ops.RemoveInput
	cmd := &cobra.Command{
		Use:     "remove --file F <alias> <entry>... --ticket T",
		Short:   "remove entries from an alias in the desired file (offline)",
		Long:    "Removes entries from one alias of the desired file and rewrites it in canonical form. Offline validation runs first; on any error nothing is written.",
		Example: "  prolexic remove --file desired.json block-v4 198.51.100.7 --ticket SEC-123",
		Args:    cobra.MinimumNArgs(2),
		RunE: a.run(func(_ context.Context, args []string) (output.Document, error) {
			in.Alias, in.Entries = args[0], args[1:]
			return output.Doc(a.ops().Remove(in))
		}),
	}
	fileFlag(cmd, &in.File)
	cmd.Flags().StringVar(&in.Ticket, "ticket", "", "the ticket authorising the change (required)")
	_ = cmd.MarkFlagRequired("ticket")
	return cmd
}

// planArgs are the flags plan and apply share.
type planArgs struct {
	file        string
	maxRemovals int
	noAnalytics bool
}

func (p *planArgs) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&p.file, "file", "", "the desired file (required)")
	f.IntVar(&p.maxRemovals, "max-removals", ncf.DefaultMaxRemovals, "most entries one alias may lose in one apply; -1 for no limit")
	f.BoolVar(&p.noAnalytics, "no-analytics-own-space", false, "skip Prolexic Analytics own space (protected prefixes, own AS numbers) in the checks; recorded in the plan")
	_ = cmd.MarkFlagRequired("file")
}

func newPlanCmd(a *app) *cobra.Command {
	var p planArgs
	var exitCode bool
	var out string
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "diff the desired file against live and validate it",
		Long: "Reads live state (read credentials only), diffs it against the desired file, runs every offline and live check, and prints the plan with its digest. " +
			"--out also saves the plan's JSON to a file (for apply --plan and verify --plan); stdout follows --format, so --format text gives a reviewer the text from the same run.",
		Args: cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return output.Doc(a.ops().Plan(ctx, ops.PlanInput{
				File: p.file, MaxRemovals: p.maxRemovals, SkipLiveOwnSpace: p.noAnalytics, ChangesAreDrift: exitCode, Out: out,
			}))
		}),
	}
	p.register(cmd)
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit 7 when the plan has changes (drift)")
	cmd.Flags().StringVar(&out, "out", "", "also save the plan's JSON to this file (stdout still follows --format)")
	return cmd
}

func newApplyCmd(a *app) *cobra.Command {
	var p planArgs
	var in ops.ApplyInput
	var cmd *cobra.Command
	cmd = &cobra.Command{
		Use:   "apply",
		Short: "apply a reviewed plan (the only command that writes)",
		Long: "Recomputes the plan and refuses unless the reviewed plan (--plan, saved by plan --out) was made from this desired file, " +
			"for this account, with these settings, and its digest still matches; then writes with the write credentials and waits for production to carry the new versions.",
		Args: cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			// The operation runs the checks the reviewed plan recorded; a
			// flag that says otherwise is refused here, by name.
			if err := checkReviewedSettings(cmd, p, in.Plan); err != nil {
				return nil, err
			}
			in.File = p.file
			return output.Doc(a.ops().Apply(ctx, in))
		}),
	}
	p.register(cmd)
	f := cmd.Flags()
	f.StringVar(&in.Plan, "plan", "", "the reviewed plan, saved by plan --out (required)")
	f.DurationVar(&in.Timeout, "timeout", ncf.DefaultApplyTimeout, "how long to wait for production to carry the new versions")
	f.DurationVar(&in.Interval, "interval", ncf.DefaultApplyInterval, "polling period while waiting")
	_ = cmd.MarkFlagRequired("plan")
	return cmd
}

func fileFlag(cmd *cobra.Command, file *string) {
	cmd.Flags().StringVar(file, "file", "", "the desired file (required)")
	_ = cmd.MarkFlagRequired("file")
}

// checkReviewedSettings refuses a --max-removals or --no-analytics-own-space
// that differs from the reviewed plan's: apply runs the plan's own checks,
// and a reviewed change must not be applied with weaker (or other) ones
// than the reviewer saw. Without either flag there is nothing to check.
func checkReviewedSettings(cmd *cobra.Command, p planArgs, planFile string) error {
	f := cmd.Flags()
	if !f.Changed("max-removals") && !f.Changed("no-analytics-own-space") {
		return nil
	}
	reviewed, err := ops.ReadPlan(planFile)
	if err != nil {
		return err
	}
	s := reviewed.Settings
	if f.Changed("max-removals") && p.maxRemovals != s.MaxRemovals {
		return apperr.New(apperr.Usage, "--max-removals %d differs from the reviewed plan's %d; re-plan with it, or drop the flag", p.maxRemovals, s.MaxRemovals)
	}
	if f.Changed("no-analytics-own-space") && p.noAnalytics != s.SkipLiveOwnSpace {
		return apperr.New(apperr.Usage, "--no-analytics-own-space=%t differs from the reviewed plan's %t; re-plan with it, or drop the flag", p.noAnalytics, s.SkipLiveOwnSpace)
	}
	return nil
}
