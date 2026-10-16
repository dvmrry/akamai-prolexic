package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
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

// ops is the operations' runtime: this invocation's clients, clock and
// progress lines on stderr.
func (a *app) ops() *ops.Runtime {
	return &ops.Runtime{
		ReadClient: a.readClient, WriteClient: a.writeClient,
		Now: a.env.Now, Sleep: a.env.Sleep, Progress: a.progress, Bogons: a.env.Bogons,
	}
}

// docOf returns an operation's document as an output.Document: a nil
// *D stays a nil interface, not a non-nil one holding a nil pointer.
func docOf[D any, P interface {
	*D
	output.Document
}](doc P, err error) (output.Document, error) {
	if doc == nil {
		return nil, err
	}
	return doc, err
}

// CommandTree is the command tree with no environment, for generated
// documentation: flag defaults are the built-in ones.
func CommandTree() *cobra.Command {
	return (&app{env: Env{Getenv: func(string) string { return "" }}}).root()
}

// root builds the command tree.
func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use:   "prolexic",
		Short: "A CLI for Akamai Prolexic",
		Long: "A CLI for Akamai Prolexic: Network Cloud Firewall aliases as a reviewed desired file, and read-only views across the Prolexic APIs.\n\n" +
			"A change: edit the desired file (add, remove), then\n" +
			"  prolexic plan --file desired.json --out plan.json     (review the plan)\n" +
			"  prolexic apply --file desired.json --plan plan.json   (writes; waits for production)\n" +
			"  prolexic verify --plan plan.json                      (reads it back)\n\n" +
			"First time: prolexic doctor --live shows which APIs your credentials can use.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return apperr.New(apperr.Usage, "unknown command %q; %s", args[0], helpHint(cmd))
			}
			return apperr.New(apperr.Usage, "missing command; %s", helpHint(cmd))
		},
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			f, err := output.ParseFormat(a.formatFlag)
			a.format = f
			a.formatChosen = cmd.Flags().Changed("format") || a.env.Getenv("PROLEXIC_FORMAT") != ""
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
		return apperr.New(apperr.Usage, "%v; %s", err, helpHint(cmd))
	})

	pf := root.PersistentFlags()
	pf.StringVar(&a.formatFlag, "format", envOr(a.env.Getenv, "PROLEXIC_FORMAT", "json"), "output format: json (the default), text for people, or auto (text on a terminal, else json) ($PROLEXIC_FORMAT)")
	pf.StringVar(&a.edgerc, "edgerc", a.env.Getenv("PROLEXIC_EDGERC"), "EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)")
	pf.StringVar(&a.section, "section", envOr(a.env.Getenv, "PROLEXIC_SECTION", "default"), "credentials section for reads ($PROLEXIC_SECTION)")
	pf.StringVar(&a.writeSection, "write-section", envOr(a.env.Getenv, "PROLEXIC_WRITE_SECTION", "write"), "credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION)")
	pf.StringVar(&a.accountKey, "account-key", a.env.Getenv("PROLEXIC_ACCOUNT_KEY"), "accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)")
	pf.StringVar(&a.caBundle, "ca-bundle", a.env.Getenv("PROLEXIC_CA_BUNDLE"), "PEM file of extra root CAs to trust, e.g. a TLS-inspecting proxy's (); verification is never turned off")
	root.AddCommand(a.tree()...)
	for _, g := range sections {
		root.AddGroup(&cobra.Group{ID: g.id, Title: g.title})
		for _, name := range g.commands {
			if c, _, err := root.Find([]string{name}); err == nil && c != root {
				c.GroupID = g.id
			}
		}
	}
	root.SetHelpCommandGroupID("setup")
	return root
}

// sections are the headings help lists the top-level commands under, by what
// they're for. Every visible top-level command belongs to one
// (TestCommandTree).
var sections = []struct {
	id, title string
	commands  []string
}{
	{"file", "Desired file:", []string{"validate", "fmt", "add", "remove", "export"}},
	{"change", "Plan, apply and verify:", []string{"plan", "apply", "verify"}},
	{"firewall", "Firewall, read-only:", []string{"status", "aliases", "acl", "rule-hits", "managed"}},
	{"analytics", "Prolexic Analytics, read-only:", []string{"routed", "attacks", "events", "metrics", "time-series", "scrub-centers", "protected", "customers"}},
	{"health", "Network Health, read-only:", []string{"targets"}},
	{"setup", "Setup:", []string{"doctor", "version"}},
}

// tree is every command of the CLI, sorted by name within each level. A new
// command is added here: its constructor, or a group of them.
func (a *app) tree() []*cobra.Command {
	return []*cobra.Command{
		group("acl", "ACL versions, rules and deployment",
			newACLDeploymentCmd(a), newACLShowCmd(a), newACLTestCmd(a), newACLVersionsCmd(a)),
		newAddCmd(a),
		group("aliases", "aliases and their versions",
			newAliasesListCmd(a), newAliasesShowCmd(a), newAliasesVersionsCmd(a)),
		newApplyCmd(a),
		group("attacks", "attack reports",
			newAttacksListCmd(a), newAttacksShowCmd(a)),
		newCustomersCmd(a),
		newDoctorCmd(a),
		newEventsCmd(a),
		newExportCmd(a),
		newFmtCmd(a),
		group("managed", "managed-services ACLs and rule hits",
			newManagedACLCmd(a), newManagedRuleHitsCmd(a)),
		newMetricsCmd(a),
		newPlanCmd(a),
		newProtectedCmd(a),
		newRemoveCmd(a),
		group("routed", "Routed BGP sessions, routes and tunnel health",
			newRoutedCheckCmd(a), newRoutedHealthCmd(a), newRoutedRoutesCmd(a), newRoutedSessionsCmd(a)),
		group("rule-hits", "ACL rule match statistics",
			newRuleHitsListCmd(a), newRuleHitsShowCmd(a)),
		newScrubCentersCmd(a),
		newStatusCmd(a),
		group("targets", "Network Health targets",
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
				return apperr.New(apperr.Usage, "unknown command %q for %q; %s", args[0], cmd.CommandPath(), helpHint(cmd))
			}
			return apperr.New(apperr.Usage, "missing subcommand for %q; %s", cmd.CommandPath(), helpHint(cmd))
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
			err = apperr.New(apperr.Usage, "%v; %s", err, helpHint(deepest(root, args)))
		}
	}
	return err
}

// deepest is the deepest command args name, or root.
func deepest(root *cobra.Command, args []string) *cobra.Command {
	cmd, _, err := root.Find(args)
	if err != nil || cmd == nil {
		return root
	}
	return cmd
}

// helpHint points a usage error at the help to read, instead of printing
// the whole usage inside the error.
func helpHint(cmd *cobra.Command) string {
	return fmt.Sprintf("run '%s --help' for usage", cmd.CommandPath())
}
