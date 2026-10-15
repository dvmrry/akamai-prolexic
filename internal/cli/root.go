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
//
// Migration: commands not yet converted are mounted as legacy leaves, which
// hand their raw arguments to the old run function to parse.

// run adapts a command body to cobra's RunE. The body returns the document
// to print and the error that decides the exit code; both may be set (a
// partial result).
func (a *app) run(body func(ctx context.Context, args []string) (output.Document, error)) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		a.ran = true
		doc, err := body(cmd.Context(), args)
		a.doc = doc
		return err
	}
}

// root builds the command tree: native commands from nativeCommands, the
// rest from the legacy table.
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
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return apperr.New(apperr.Usage, "%v\n%s", err, cmd.UsageString())
	})

	pf := root.PersistentFlags()
	pf.StringVar(&a.formatFlag, "format", "auto", "output format: auto (text on a terminal, else json), json or text")
	pf.StringVar(&a.edgerc, "edgerc", a.env.Getenv("PROLEXIC_EDGERC"), "EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)")
	pf.StringVar(&a.section, "section", envOr(a.env.Getenv, "PROLEXIC_SECTION", "default"), "credentials section for reads ($PROLEXIC_SECTION)")
	pf.StringVar(&a.writeSection, "write-section", envOr(a.env.Getenv, "PROLEXIC_WRITE_SECTION", "write"), "credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION)")
	pf.StringVar(&a.accountKey, "account-key", a.env.Getenv("PROLEXIC_ACCOUNT_KEY"), "accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)")

	native := nativeCommands()
	for _, c := range commands() {
		root.AddCommand(a.mount(c, nil, native))
	}
	return root
}

// mount turns one entry of the legacy table into a cobra command, using the
// native constructor for its path when there is one.
func (a *app) mount(c *command, parent []string, native map[string]func(*app) *cobra.Command) *cobra.Command {
	path := append(append([]string{}, parent...), c.name)
	if build, ok := native[strings.Join(path, " ")]; ok {
		return build(a)
	}
	if c.run != nil {
		run := c.run
		return &cobra.Command{
			Use:                c.name,
			Short:              c.summary,
			DisableFlagParsing: true, // the legacy run function parses its own flags
			RunE: a.run(func(ctx context.Context, args []string) (output.Document, error) {
				a.path = strings.Join(path, " ")
				return run(ctx, a, args)
			}),
		}
	}
	group := newGroup(c.name, c.summary)
	for _, sub := range c.sub {
		group.AddCommand(a.mount(sub, path, native))
	}
	return group
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

// nativeCommands are the converted commands, by path.
func nativeCommands() map[string]func(*app) *cobra.Command {
	return map[string]func(*app) *cobra.Command{
		"add":   newAddCmd,
		"apply": newApplyCmd, "export": newExportCmd, "fmt": newFmtCmd, "remove": newRemoveCmd, "validate": newValidateCmd,
		"doctor":          newDoctorCmd,
		"plan":            newPlanCmd,
		"routed sessions": newRoutedSessionsCmd, "routed check": newRoutedCheckCmd, "routed health": newRoutedHealthCmd, "routed routes": newRoutedRoutesCmd,
		"version": newVersionCmd,
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
