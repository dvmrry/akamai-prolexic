// Package cli is the prolexic command tree: argument parsing, credential and
// client wiring, and the output contract (one Document on stdout, an error
// document on stderr, a stable exit code).
//
// A command is a leaf function that parses its flags with a.flags/a.parse,
// does its work and returns a Document. It never writes to stdout itself. A
// command that produced a partial result returns both the document and an
// error: the document is printed and the error decides the exit code.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// Env is the process environment, injectable for tests.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Home           string // "" means os.UserHomeDir
	Now            func() time.Time
	Sleep          func(context.Context, time.Duration) error // nil means a real, cancellable sleep
	// Bogons overrides the bogon list (tests drop the documentation ranges
	// their fixtures use); nil means ncf.Bogons.
	Bogons []netip.Prefix

	// Transport and Scheme let tests point clients at an httptest server.
	Transport http.RoundTripper
	Scheme    string
}

// OSEnv is the real environment.
func OSEnv() Env {
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Now: time.Now}
}

type command struct {
	name    string
	summary string
	sub     []*command
	run     func(ctx context.Context, a *app, args []string) (output.Document, error)
}

// commands is the whole tree. Keep it sorted by name within each level.
func commands() []*command {
	return []*command{
		{name: "acl", summary: "ACL versions, rules and deployment (read-only)", sub: []*command{
			{name: "deployment", summary: "deployment-status rulesets and which is in production", run: runACLDeployment},
			{name: "show", summary: "one ACL version's rules (default: production)", run: runACLShow},
			{name: "versions", summary: "every ACL version", run: runACLVersions},
		}},
		{name: "add"},
		{name: "aliases", summary: "aliases and their versions (read-only)", sub: []*command{
			{name: "list", summary: "every alias, without entries", run: runAliasesList},
			{name: "show", summary: "one alias's entries at a version", run: runAliasesShow},
			{name: "versions", summary: "one alias's version history", run: runAliasesVersions},
		}},
		{name: "apply", summary: "apply a reviewed plan (the only command that writes)", run: runApply},
		{name: "attacks", summary: "attack reports (read-only)", sub: []*command{
			{name: "list", summary: "attacks in a time window per customer name", run: runAttacksList},
			{name: "show", summary: "one attack's detail report", run: runAttacksShow},
		}},
		{name: "customers", summary: "the account's customer names (read-only)", run: runCustomers},
		{name: "doctor"},
		{name: "events", summary: "critical events and events per customer name", run: runEvents},
		{name: "export", summary: "write live editable aliases to the desired file (bootstrap, or adopt drift)", run: runExport},
		{name: "fmt", summary: "rewrite the desired file in canonical form, or --check it (offline)", run: runFmt},
		{name: "managed", summary: "managed-services ACLs and rule hits (read-only)", sub: []*command{
			{name: "acl", summary: "a policy domain's latest managed-services ACL version", run: runManagedACL},
			{name: "rule-hits", summary: "a policy domain's rule statistics, and one rule's time series", run: runManagedRuleHits},
		}},
		{name: "metrics", summary: "traffic metrics per customer name (read-only)", run: runMetrics},
		{name: "plan"},
		{name: "protected", summary: "prefixes and AS numbers treated as own space, per customer name (read-only)", run: runProtected},
		{name: "remove", summary: "remove entries from an alias in the desired file (offline)", run: runRemove},
		{name: "routed", summary: "Routed BGP sessions, routes and tunnel health (read-only)", sub: []*command{
			{name: "check", summary: "check a prefix has propagated (or gone) on every session", run: runRoutedCheck},
			{name: "health", summary: "healthy and total tunnels per location and router", run: runRoutedHealth},
			{name: "routes", summary: "routes announced to Akamai per customer name", run: runRoutedRoutes},
			{name: "sessions"},
		}},
		{name: "rule-hits", summary: "ACL rule match statistics (read-only)", sub: []*command{
			{name: "list", summary: "match statistics of every rule", run: runRuleHitsList},
			{name: "show", summary: "one rule's statistics, and its time series with a window", run: runRuleHitsShow},
		}},
		{name: "scrub-centers", summary: "active scrub centers (read-only)", run: runScrubCenters},
		{name: "status", summary: "deployment state, aliases and limits (read-only)", run: runStatus},
		{name: "targets", summary: "Network Health targets (read-only)", sub: []*command{
			{name: "list", summary: "every target of the account", run: runTargetsList},
			{name: "show", summary: "one target by id", run: runTargetsShow},
		}},
		{name: "time-series", summary: "flow usage and attack traffic per destination (read-only)", run: runTimeSeries},
		{name: "validate", summary: "offline checks of the desired file: no credentials, no network", run: runValidate},
		{name: "version"},
	}
}

// app is one invocation's state: the environment plus the common flags.
type app struct {
	env    Env
	path   string // "routed sessions", for messages
	format output.Format

	edgerc       string
	section      string
	writeSection string
	accountKey   string

	formatFlag string          // --format as given; parsed into format before a command runs
	doc        output.Document // what the command returned, printed by Run
	ran        bool            // a command body ran (so an error is its own, not a usage error)
}

// Run executes args and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Sleep == nil {
		env.Sleep = sleep
	}
	a := &app{env: env, format: output.Auto}
	if len(args) > 0 && args[0] == "--version" {
		args = append([]string{"version"}, args[1:]...)
	}
	err := a.execute(ctx, args)
	if doc := a.doc; doc != nil {
		if werr := output.Write(env.Stdout, a.format, doc); werr != nil && err == nil {
			err = werr
		}
	}
	if err != nil {
		return a.fail(err)
	}
	return int(apperr.OK)
}

func (a *app) fail(err error) int {
	var help *helpRequest
	if errors.As(err, &help) {
		fmt.Fprint(a.env.Stdout, help.text)
		return int(apperr.OK)
	}
	if werr := output.Write(a.env.Stderr, a.format, output.NewErrorDoc(err)); werr != nil {
		fmt.Fprintf(a.env.Stderr, "prolexic: %v\n", err)
	}
	return int(apperr.CodeOf(err))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// helpRequest is returned for -h/--help/help; it prints usage and exits 0.
type helpRequest struct{ text string }

func (h *helpRequest) Error() string { return "help requested" }

func find(cmds []*command, args []string) (*command, []string, string, error) {
	var path []string
	for {
		if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
			text := usage(path, cmds)
			if len(args) == 0 {
				return nil, nil, "", apperr.New(apperr.Usage, "missing command\n%s", text)
			}
			return nil, nil, "", &helpRequest{text}
		}
		if len(path) == 0 && args[0] == "--version" {
			args[0] = "version"
		}
		var next *command
		for _, c := range cmds {
			if c.name == args[0] {
				next = c
			}
		}
		if next == nil {
			return nil, nil, "", apperr.New(apperr.Usage, "unknown command %q\n%s", strings.Join(append(path, args[0]), " "), usage(path, cmds))
		}
		path = append(path, next.name)
		args = args[1:]
		if next.run != nil {
			return next, args, strings.Join(path, " "), nil
		}
		cmds = next.sub
	}
}

func usage(path []string, cmds []*command) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: prolexic %s<command> [flags]\n\ncommands:\n", prefix(path))
	for _, c := range cmds {
		fmt.Fprintf(&b, "  %-10s %s\n", c.name, c.summary)
	}
	return b.String()
}

func prefix(path []string) string {
	if len(path) == 0 {
		return ""
	}
	return strings.Join(path, " ") + " "
}

// flags returns a FlagSet for the current command with the common flags
// registered. Defaults come from the environment.
func (a *app) flags() *flag.FlagSet {
	fs := flag.NewFlagSet("prolexic "+a.path, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Func("format", "output format: auto (text on a terminal, else json), json or text", func(s string) error {
		f, err := output.ParseFormat(s)
		a.format = f
		return err
	})
	fs.StringVar(&a.edgerc, "edgerc", a.env.Getenv("PROLEXIC_EDGERC"), "EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)")
	fs.StringVar(&a.section, "section", envOr(a.env.Getenv, "PROLEXIC_SECTION", "default"), "credentials section for reads ($PROLEXIC_SECTION)")
	fs.StringVar(&a.writeSection, "write-section", envOr(a.env.Getenv, "PROLEXIC_WRITE_SECTION", "write"), "credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION)")
	fs.StringVar(&a.accountKey, "account-key", a.env.Getenv("PROLEXIC_ACCOUNT_KEY"), "accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)")
	return fs
}

// parse parses args, mapping flag errors to usage errors and -h to help. It
// rejects positional arguments unless the command opts in by passing
// allowArgs.
func (a *app) parse(fs *flag.FlagSet, args []string, allowArgs bool) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &helpRequest{flagUsage(fs)}
		}
		var ae *apperr.Error
		if errors.As(err, &ae) {
			return ae
		}
		return apperr.New(apperr.Usage, "%v\n%s", err, flagUsage(fs))
	}
	if !allowArgs && fs.NArg() > 0 {
		return apperr.New(apperr.Usage, "unexpected argument %q\n%s", fs.Arg(0), flagUsage(fs))
	}
	return nil
}

func flagUsage(fs *flag.FlagSet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: %s [flags]\n\nflags:\n", fs.Name())
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
	return b.String()
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// credentials resolves one section, applying --account-key.
func (a *app) credentials(section string) (edgegrid.Credentials, edgegrid.Source, error) {
	c, src, err := edgegrid.Load(edgegrid.Options{Section: section, Edgerc: a.edgerc, Getenv: a.env.Getenv, Home: a.env.Home})
	if err != nil {
		return c, src, err
	}
	if a.accountKey != "" {
		c.AccountKey = a.accountKey
	}
	return c, src, nil
}

// readClient is the API client for reads.
func (a *app) readClient() (*akamai.Client, error) {
	return a.client(a.section)
}

// writeClient is the API client for writes. Only apply may call it: CI hands
// the write credentials to the apply job alone.
func (a *app) writeClient() (*akamai.Client, error) {
	return a.client(a.writeSection)
}

func (a *app) client(section string) (*akamai.Client, error) {
	c, _, err := a.credentials(section)
	if err != nil {
		return nil, err
	}
	return akamai.New(c, akamai.Options{Base: a.env.Transport, Scheme: a.env.Scheme}), nil
}

// stringList is a repeatable flag that also splits on commas.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(s string) error {
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
		}
	}
	return nil
}
