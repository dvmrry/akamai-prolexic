package cli

import (
	"context"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// The command tree is Cobra. A command declares its flags up front on its
// cobra.Command (so the tree can be walked: help, completions, generated
// docs and tool schemas) and runs through a.run, which records the
// Document it returns; Run prints it and the error, and maps the error to
// the exit code. A command never writes to stdout itself.

// run adapts a command body to cobra's RunE. The body returns the document
// to print and the error that decides the exit code; both may be set (a
// partial result).
func (a *app) run(body func(ctx context.Context, args []string) (output.Document, error)) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		a.ran = true
		doc, err := body(cmd.Context(), args)
		a.doc = doc
		if o, ok := doc.(outcomer); ok && err == nil {
			err = o.Outcome()
		}
		return err
	}
}

// CommandTree is the command tree with no environment, for generated
// documentation: flag defaults are the built-in ones.
func CommandTree() *cobra.Command {
	return (&app{env: Env{Getenv: func(string) string { return "" }}}).root()
}

// root builds the command tree.
func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use:           "prolexic",
		Short:         "A CLI for Akamai Prolexic",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return apperr.New(apperr.Usage, "unknown command %q\n%s", args[0], cmd.UsageString())
			}
			return apperr.New(apperr.Usage, "missing command\n%s", cmd.UsageString())
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			f, err := output.ParseFormat(a.formatFlag)
			a.format = f
			return err
		},
	}
	root.CompletionOptions.HiddenDefaultCmd = true
	// help for an unknown topic is a usage error (exit 2), not root help with
	// exit 0.
	root.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "help about any command",
		Args:  cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			target, rest, err := c.Root().Find(args)
			if err != nil || len(rest) > 0 || (len(args) > 0 && target == c.Root()) {
				return apperr.New(apperr.Usage, "unknown help topic %q", strings.Join(args, " "))
			}
			return target.Help()
		},
	})
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return apperr.New(apperr.Usage, "%v\n%s", err, cmd.UsageString())
	})

	pf := root.PersistentFlags()
	pf.StringVar(&a.formatFlag, "format", "auto", "output format: auto (text on a terminal, else json), json or text")
	pf.StringVar(&a.edgerc, "edgerc", a.env.Getenv("PROLEXIC_EDGERC"), "EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)")
	pf.StringVar(&a.section, "section", envOr(a.env.Getenv, "PROLEXIC_SECTION", "default"), "credentials section for reads ($PROLEXIC_SECTION)")
	pf.StringVar(&a.writeSection, "write-section", envOr(a.env.Getenv, "PROLEXIC_WRITE_SECTION", "write"), "credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION)")
	pf.StringVar(&a.accountKey, "account-key", a.env.Getenv("PROLEXIC_ACCOUNT_KEY"), "accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)")
	root.AddCommand(a.tree()...)
	return root
}

// tree is every command of the CLI, sorted by name within each level. A new
// command is added here: its constructor, or a group of them.
func (a *app) tree() []*cobra.Command {
	return []*cobra.Command{
		group("acl", "ACL versions, rules and deployment (read-only)",
			newACLDeploymentCmd(a), newACLShowCmd(a), newACLTestCmd(a), newACLVersionsCmd(a)),
		newAddCmd(a),
		group("aliases", "aliases and their versions (read-only)",
			newAliasesListCmd(a), newAliasesShowCmd(a), newAliasesVersionsCmd(a)),
		newApplyCmd(a),
		group("attacks", "attack reports (read-only)",
			newAttacksListCmd(a), newAttacksShowCmd(a)),
		newCustomersCmd(a),
		newDoctorCmd(a),
		newEventsCmd(a),
		newExportCmd(a),
		newFmtCmd(a),
		group("managed", "managed-services ACLs and rule hits (read-only)",
			newManagedACLCmd(a), newManagedRuleHitsCmd(a)),
		newMetricsCmd(a),
		newPlanCmd(a),
		newProtectedCmd(a),
		newRemoveCmd(a),
		group("routed", "Routed BGP sessions, routes and tunnel health (read-only)",
			newRoutedCheckCmd(a), newRoutedHealthCmd(a), newRoutedRoutesCmd(a), newRoutedSessionsCmd(a)),
		group("rule-hits", "ACL rule match statistics (read-only)",
			newRuleHitsListCmd(a), newRuleHitsShowCmd(a)),
		newScrubCentersCmd(a),
		newStatusCmd(a),
		group("targets", "Network Health targets (read-only)",
			newTargetsListCmd(a), newTargetsShowCmd(a)),
		newTimeSeriesCmd(a),
		newValidateCmd(a),
		newVerifyCmd(a),
		newVersionCmd(a),
	}
}

// group is a command that only holds the given subcommands.
func group(name, short string, subs ...*cobra.Command) *cobra.Command {
	g := newGroup(name, short)
	g.AddCommand(subs...)
	return g
}

// newGroup is a command that only holds subcommands: run bare or with an
// unknown subcommand, it is a usage error (exit 2), not help.
func newGroup(name, short string) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: short,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return apperr.New(apperr.Usage, "unknown command %q for %q\n%s", args[0], cmd.CommandPath(), cmd.UsageString())
			}
			return apperr.New(apperr.Usage, "missing subcommand for %q\n%s", cmd.CommandPath(), cmd.UsageString())
		},
	}
}

// execute runs the tree on args and returns the error to report: a cobra
// error before any command ran (unknown command or flag, bad arguments) is a
// usage error.
func (a *app) execute(ctx context.Context, args []string) error {
	root := a.root()
	root.SetArgs(args)
	root.SetOut(a.env.Stdout)
	root.SetErr(a.env.Stderr)
	err := root.ExecuteContext(ctx)
	if err != nil && !a.ran {
		var ae *apperr.Error
		if !errors.As(err, &ae) {
			err = apperr.New(apperr.Usage, "%v\n%s", err, usageFor(root, args))
		}
	}
	return err
}

// usageFor is the usage of the deepest command args name.
func usageFor(root *cobra.Command, args []string) string {
	cmd, _, err := root.Find(args)
	if err != nil || cmd == nil {
		cmd = root
	}
	return cmd.UsageString()
}
