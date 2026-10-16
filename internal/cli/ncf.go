package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfanalytics"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// The desired-file commands. validate, fmt, add and remove are offline: no
// credentials, no network. plan reads; apply alone writes.

// ValidateDoc is the result of the offline checks.
type ValidateDoc struct {
	output.Header
	File     string        `json:"file"`
	Valid    bool          `json:"valid" doc:"No error findings."`
	Findings []ncf.Finding `json:"findings"`
}

func (*ValidateDoc) SchemaID() string { return "prolexic.validate.v1" }

func (d *ValidateDoc) Outcome() error {
	if !d.Valid {
		return apperr.New(apperr.Validation, "%s has errors", d.File)
	}
	return nil
}

func (d *ValidateDoc) WriteText(w io.Writer) error {
	if err := writeFindings(w, d.Findings); err != nil {
		return err
	}
	verdict := "valid"
	if !d.Valid {
		verdict = "INVALID"
	}
	_, err := fmt.Fprintf(w, "%s: %s\n", d.File, verdict)
	return err
}

func newValidateCmd(a *app) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "offline checks of the desired file: no credentials, no network",
		Args:  cobra.NoArgs,
		RunE: a.run(func(context.Context, []string) (output.Document, error) {
			return validate(a, file)
		}),
	}
	fileFlag(cmd, &file)
	return cmd
}

func validate(a *app, file string) (output.Document, error) {
	f, raw, err := readDesired(file)
	if err != nil {
		return nil, err
	}
	doc := &ValidateDoc{File: file, Findings: nonNil(a.checker().Validate(f, raw))}
	doc.Valid = !ncf.HasErrors(doc.Findings)
	return doc, nil
}

// FmtDoc is the result of fmt.
type FmtDoc struct {
	output.Header
	File      string `json:"file"`
	Canonical bool   `json:"canonical" doc:"Whether the file was already canonical."`
	Written   bool   `json:"written"`

	check bool // --check: a file that isn't canonical is an error, not rewritten
}

func (*FmtDoc) SchemaID() string { return "prolexic.fmt.v1" }

func (d *FmtDoc) Outcome() error {
	if d.check && !d.Canonical {
		return apperr.New(apperr.Validation, "%s is not in canonical form; run prolexic fmt", d.File)
	}
	return nil
}

func (d *FmtDoc) WriteText(w io.Writer) error {
	var err error
	switch {
	case d.Canonical:
		_, err = fmt.Fprintf(w, "%s: canonical\n", d.File)
	case d.Written:
		_, err = fmt.Fprintf(w, "%s: rewritten in canonical form\n", d.File)
	default:
		_, err = fmt.Fprintf(w, "%s: NOT canonical\n", d.File)
	}
	return err
}

func newFmtCmd(a *app) *cobra.Command {
	var file string
	var check bool
	cmd := &cobra.Command{
		Use:   "fmt",
		Short: "rewrite the desired file in canonical form, or --check it (offline)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(context.Context, []string) (output.Document, error) {
			return format(file, check)
		}),
	}
	fileFlag(cmd, &file)
	cmd.Flags().BoolVar(&check, "check", false, "fail if the file isn't canonical; write nothing")
	return cmd
}

func format(file string, check bool) (output.Document, error) {
	f, raw, err := readDesired(file)
	if err != nil {
		return nil, err
	}
	canon, err := ncf.Canonical(f)
	if err != nil {
		return nil, err
	}
	doc := &FmtDoc{File: file, Canonical: bytes.Equal(raw, canon), check: check}
	if doc.Canonical || check {
		return doc, nil
	}
	if err := writeFileAtomic(file, canon); err != nil {
		return nil, err
	}
	doc.Written = true
	return doc, nil
}

// ChangeDoc is the result of add or remove: what changed in the file, and
// the findings that decided whether it was written.
type ChangeDoc struct {
	output.Header
	File     string        `json:"file"`
	Action   string        `json:"action" enum:"add,remove"`
	Alias    string        `json:"alias"`
	Ticket   string        `json:"ticket"`
	Entries  []ncf.Entry   `json:"entries" doc:"The entries added, or removed with the metadata they had."`
	Written  bool          `json:"written" doc:"False when a finding blocked the change; the file is untouched."`
	Findings []ncf.Finding `json:"findings"`
}

func (*ChangeDoc) SchemaID() string { return "prolexic.change.v1" }

func (d *ChangeDoc) Outcome() error {
	if !d.Written {
		return apperr.New(apperr.Validation, "%s: not written", d.File)
	}
	return nil
}

func (d *ChangeDoc) WriteText(w io.Writer) error {
	sign := "+"
	if d.Action == "remove" {
		sign = "-"
	}
	for _, e := range d.Entries {
		fmt.Fprintf(w, "%s %s %s\n", sign, d.Alias, e.CIDR)
	}
	if err := writeFindings(w, d.Findings); err != nil {
		return err
	}
	verdict := "written"
	if !d.Written {
		verdict = "NOT written"
	}
	_, err := fmt.Fprintf(w, "%s: %s (ticket %s)\n", d.File, verdict, d.Ticket)
	return err
}

// addArgs are add's flags.
type addArgs struct {
	file, ticket, reason, expires string
}

func newAddCmd(a *app) *cobra.Command {
	var p addArgs
	cmd := &cobra.Command{
		Use:     "add --file F <alias> <entry>... --ticket T --reason R [--expires YYYY-MM-DD]",
		Short:   "add entries to an alias in the desired file (offline)",
		Long:    "Adds entries, with ticket, reason and date metadata, to one alias of the desired file and rewrites it in canonical form. Offline validation runs first; on any error, or a warning about an added entry, nothing is written.",
		Example: "  prolexic add --file desired.json block-v4 198.51.100.7 --ticket SEC-123 --reason scanner",
		Args:    cobra.MinimumNArgs(2),
		RunE: a.run(func(_ context.Context, args []string) (output.Document, error) {
			return add(a, p, args)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&p.file, "file", "", "the desired file (required)")
	f.StringVar(&p.ticket, "ticket", "", "the ticket authorising the change (required)")
	f.StringVar(&p.reason, "reason", "", "why the entries are added (required)")
	f.StringVar(&p.expires, "expires", "", "YYYY-MM-DD after which the entries are flagged as expired")
	for _, name := range []string{"file", "ticket", "reason"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func add(a *app, args addArgs, pos []string) (output.Document, error) {
	if args.expires != "" {
		if _, err := ncf.ParseDate(args.expires); err != nil {
			return nil, apperr.New(apperr.Usage, "--expires %q is not YYYY-MM-DD", args.expires)
		}
	}
	f, raw, err := readDesired(args.file)
	if err != nil {
		return nil, err
	}
	doc := &ChangeDoc{File: args.file, Action: "add", Alias: pos[0], Ticket: args.ticket, Entries: []ncf.Entry{}, Findings: []ncf.Finding{}}
	alias, err := findAlias(f, pos[0])
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, e := range alias.Entries {
		if v, err := ncf.ParseAuthored(e.CIDR); err == nil {
			have[v.String()] = true
		}
	}
	added := map[string]bool{}
	today := a.env.Now().UTC().Format(time.DateOnly)
	for _, s := range pos[1:] {
		v, err := ncf.ParseAuthored(s)
		if err != nil {
			doc.Findings = append(doc.Findings, ncf.Finding{Severity: ncf.Error, Code: "entry", Alias: alias.Name, Entry: s, Message: err.Error()})
			continue
		}
		key := v.String()
		if have[key] || added[key] {
			doc.Findings = append(doc.Findings, ncf.Finding{Severity: ncf.Error, Code: "already_present", Alias: alias.Name, Entry: key, Message: key + " is already in the alias"})
			continue
		}
		added[key] = true
		e := ncf.Entry{CIDR: key, Ticket: args.ticket, Reason: args.reason, Added: today, Expires: args.expires}
		alias.Entries = append(alias.Entries, e)
		doc.Entries = append(doc.Entries, e)
	}
	return a.commitChange(doc, f, raw, added)
}

func newRemoveCmd(a *app) *cobra.Command {
	var file, ticket string
	cmd := &cobra.Command{
		Use:     "remove --file F <alias> <entry>... --ticket T",
		Short:   "remove entries from an alias in the desired file (offline)",
		Long:    "Removes entries from one alias of the desired file and rewrites it in canonical form. Offline validation runs first; on any error nothing is written.",
		Example: "  prolexic remove --file desired.json block-v4 198.51.100.7 --ticket SEC-123",
		Args:    cobra.MinimumNArgs(2),
		RunE: a.run(func(_ context.Context, args []string) (output.Document, error) {
			return remove(a, file, ticket, args)
		}),
	}
	fileFlag(cmd, &file)
	cmd.Flags().StringVar(&ticket, "ticket", "", "the ticket authorising the change (required)")
	_ = cmd.MarkFlagRequired("ticket")
	return cmd
}

func remove(a *app, file, ticket string, pos []string) (output.Document, error) {
	f, raw, err := readDesired(file)
	if err != nil {
		return nil, err
	}
	doc := &ChangeDoc{File: file, Action: "remove", Alias: pos[0], Ticket: ticket, Entries: []ncf.Entry{}, Findings: []ncf.Finding{}}
	alias, err := findAlias(f, pos[0])
	if err != nil {
		return nil, err
	}
	for _, s := range pos[1:] {
		v, err := ncf.ParseAuthored(s)
		if err != nil {
			doc.Findings = append(doc.Findings, ncf.Finding{Severity: ncf.Error, Code: "entry", Alias: alias.Name, Entry: s, Message: err.Error()})
			continue
		}
		key := v.String()
		i := slices.IndexFunc(alias.Entries, func(e ncf.Entry) bool {
			w, err := ncf.ParseAuthored(e.CIDR)
			return err == nil && w.String() == key
		})
		if i < 0 {
			doc.Findings = append(doc.Findings, ncf.Finding{Severity: ncf.Error, Code: "not_present", Alias: alias.Name, Entry: key, Message: key + " is not in the alias"})
			continue
		}
		doc.Entries = append(doc.Entries, alias.Entries[i])
		alias.Entries = slices.Delete(alias.Entries, i, i+1)
	}
	return a.commitChange(doc, f, raw, nil)
}

// commitChange validates the changed file and writes it canonically, or
// writes nothing. Any error blocks, and so does a warning about an entry
// this change adds; warnings about untouched entries are reported only.
func (a *app) commitChange(doc *ChangeDoc, f *ncf.File, raw []byte, added map[string]bool) (output.Document, error) {
	if pre, _, err := ncf.Decode(bytes.NewReader(raw)); err == nil {
		if canon, err := ncf.Canonical(pre); err == nil && !bytes.Equal(canon, raw) {
			doc.Findings = append(doc.Findings, ncf.Finding{Severity: ncf.Error, Code: "not_canonical", Message: "the file was hand-edited (not canonical); run prolexic fmt and review before changing it"})
		}
	}
	doc.Findings = append(doc.Findings, a.checker().Validate(f, nil)...)
	blocked := slices.ContainsFunc(doc.Findings, func(x ncf.Finding) bool {
		return x.Severity == ncf.Error || (x.Alias == doc.Alias && added[x.Entry])
	})
	if blocked {
		return doc, nil // not written: Outcome reports it
	}
	canon, err := ncf.Canonical(f)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(doc.File, canon); err != nil {
		return nil, err
	}
	doc.Written = true
	return doc, nil
}

// PlanDoc is a plan: the diff of the desired file against live.
type PlanDoc struct {
	output.Header
	File string `json:"file"`
	ncf.Plan
	OwnSpaceAnalytics bool `json:"ownSpaceAnalytics" doc:"Whether Prolexic Analytics protected prefixes were part of the own-space check."`

	changesAreDrift bool // --exit-code: changes exit as drift
}

func (*PlanDoc) SchemaID() string { return "prolexic.plan.v1" }

func (d *PlanDoc) Outcome() error {
	switch {
	case ncf.HasErrors(d.Findings):
		return apperr.New(apperr.Validation, "the plan has errors")
	case d.changesAreDrift && d.Changes:
		return apperr.New(apperr.Drift, "live differs from %s", d.File)
	}
	return nil
}

func (d *PlanDoc) WriteText(w io.Writer) error {
	for _, al := range d.Aliases {
		if !al.Changed() {
			fmt.Fprintf(w, "  %s (%d): no changes; role %s (from %s)\n", al.Name, al.ID, al.Role, al.RoleSource)
			continue
		}
		fmt.Fprintf(w, "~ %s (%d) %s %s, activeVersion %s\n", al.Name, al.ID, al.Type, al.IPVersion, dash(al.ActiveVersion))
		fmt.Fprintf(w, "    role %s (from %s)\n", al.Role, al.RoleSource)
		for _, e := range al.Add {
			meta := ""
			if e.Ticket != "" {
				meta = "  # " + e.Ticket
			}
			fmt.Fprintf(w, "    + %s%s\n", e.CIDR, meta)
		}
		for _, e := range al.Remove {
			fmt.Fprintf(w, "    - %s\n", e.CIDR)
		}
	}
	if err := writeFindings(w, d.Findings); err != nil {
		return err
	}
	if err := writeChecks(w, d.Checks, d.OwnSpaceAnalytics); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\ndigest: %s\n", d.Digest)
	return err
}

// writeChecks says what the live checks ran against, so a clean plan reads
// as checked, not merely as free of errors.
func writeChecks(w io.Writer, c ncf.Checks, analytics bool) error {
	var sources []string
	total := 0
	for _, s := range c.OwnSpace {
		sources = append(sources, fmt.Sprintf("%d %s", s.Prefixes, s.Source))
		total += s.Prefixes
	}
	ownSpace := "none"
	if total > 0 {
		ownSpace = fmt.Sprintf("%d prefixes (%s)", total, strings.Join(sources, ", "))
	}
	if !analytics {
		ownSpace += "; Prolexic Analytics skipped"
	}
	if !c.LiveChecksRan {
		_, err := fmt.Fprintln(w, "\nlive checks didn't run: the offline checks failed")
		return err
	}
	_, err := fmt.Fprintf(w, "\nchecked against: own space %s; %d own AS numbers; %d deployed ACL rules\n", ownSpace, c.OwnASNs, c.DeployedRules)
	return err
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
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "diff the desired file against live and validate it",
		Long:  "Reads live state (read credentials only), diffs it against the desired file, runs every offline and live check, and prints the plan with its digest. apply --expect-digest takes that digest.",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return plan(ctx, a, p, exitCode)
		}),
	}
	p.register(cmd)
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit 7 when the plan has changes (drift)")
	return cmd
}

func plan(ctx context.Context, a *app, args planArgs, exitCode bool) (output.Document, error) {
	f, raw, err := readDesired(args.file)
	if err != nil {
		return nil, err
	}
	store, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	p, err := a.checker().MakePlan(ctx, store, f, raw, a.planOptions(args.maxRemovals, args.noAnalytics))
	if err != nil {
		return nil, err
	}
	return &PlanDoc{File: args.file, Plan: *p, OwnSpaceAnalytics: !args.noAnalytics, changesAreDrift: exitCode}, nil
}

// ApplyDoc is the result of apply.
type ApplyDoc struct {
	output.Header
	File   string           `json:"file"`
	Result *ncf.ApplyResult `json:"result,omitempty" doc:"Absent when apply refused before writing (plan errors, digest moved)."`
	Plan   *ncf.Plan        `json:"plan,omitempty" doc:"The fresh plan apply computed."`
}

func (*ApplyDoc) SchemaID() string { return "prolexic.apply.v1" }

func (d *ApplyDoc) WriteText(w io.Writer) error {
	if d.Result == nil {
		if d.Plan != nil {
			return writeFindings(w, d.Plan.Findings)
		}
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ALIAS\tID\tSTATUS\tFROM\tVERSION\t+\t-\tTO PRODUCTION")
	for _, al := range d.Result.Aliases {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t%d\t%s\n", al.Name, al.ID, al.Status, dash(al.FromVersion), dash(al.Version), len(al.Add), len(al.Remove), toProduction(al))
	}
	return tw.Flush()
}

func newApplyCmd(a *app) *cobra.Command {
	var p planArgs
	var expect string
	var timeout, interval time.Duration
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "apply a reviewed plan (the only command that writes)",
		Long:  "Recomputes the plan, refuses unless its digest equals --expect-digest (the digest of the plan you reviewed), then writes with the write credentials and waits for production to carry the new versions.",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return apply(ctx, a, p, expect, timeout, interval)
		}),
	}
	p.register(cmd)
	f := cmd.Flags()
	f.StringVar(&expect, "expect-digest", "", "the digest of the reviewed plan (required)")
	f.DurationVar(&timeout, "timeout", ncf.DefaultApplyTimeout, "how long to wait for production to carry the new versions")
	f.DurationVar(&interval, "interval", ncf.DefaultApplyInterval, "polling period while waiting")
	_ = cmd.MarkFlagRequired("expect-digest")
	return cmd
}

func apply(ctx context.Context, a *app, args planArgs, expect string, timeout, interval time.Duration) (output.Document, error) {
	f, raw, err := readDesired(args.file)
	if err != nil {
		return nil, err
	}
	read, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	wc, err := a.writeClient()
	if err != nil {
		return nil, err
	}
	p, res, err := a.checker().Apply(ctx, read, a.ncfStore(wc), f, raw, ncf.ApplyOptions{
		PlanOptions: a.planOptions(args.maxRemovals, args.noAnalytics), ExpectDigest: expect, Timeout: timeout, Interval: interval,
		Sleep: a.env.Sleep, Now: a.env.Now, Progress: func(p ncf.Progress) { a.progress(p.Message) },
	})
	if p == nil && res == nil {
		return nil, err
	}
	return &ApplyDoc{File: args.file, Plan: p, Result: res}, err
}

// planOptions builds the plan options: live own space from Prolexic Analytics
// (ncfanalytics), unless --no-analytics-own-space skips it.
func (a *app) planOptions(maxRemovals int, noAnalytics bool) ncf.PlanOptions {
	if noAnalytics {
		return ncf.PlanOptions{MaxRemovals: maxRemovals, SkipLiveOwnSpace: true}
	}
	return ncf.PlanOptions{MaxRemovals: maxRemovals, LiveOwnSpace: ncfanalytics.Source(a.analytics)}
}

func (a *app) checker() *ncf.Checker {
	c := ncf.NewChecker(a.env.Now())
	if a.env.Bogons != nil {
		c.Bogons = a.env.Bogons
	}
	return c
}

// ncfRead is the NCF store over the read credentials.
func (a *app) ncfRead() (ncf.Store, error) {
	c, err := a.readClient()
	if err != nil {
		return nil, err
	}
	return a.ncfStore(c), nil
}

// ncfStore returns the NCF adapter (v2; v1 is retired).
func (a *app) ncfStore(c *akamai.Client) ncf.Store {
	return ncfapi.NewV2(c)
}

func fileFlag(cmd *cobra.Command, file *string) {
	cmd.Flags().StringVar(file, "file", "", "the desired file (required)")
	_ = cmd.MarkFlagRequired("file")
}

func readDesired(path string) (*ncf.File, []byte, error) {
	if path == "" {
		return nil, nil, apperr.New(apperr.Usage, "--file is required")
	}
	fh, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, apperr.New(apperr.NotFound, "no desired file %s", path)
	}
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.Usage, err, "open %s", path)
	}
	defer fh.Close()
	return ncf.Decode(fh)
}

func findAlias(f *ncf.File, name string) (*ncf.Alias, error) {
	for i := range f.Aliases {
		if f.Aliases[i].Name == name {
			return &f.Aliases[i], nil
		}
	}
	return nil, apperr.New(apperr.Validation, "no alias %q in the desired file", name)
}

// writeFileAtomic replaces path with b via a temporary file in the same
// directory, keeping the file's mode.
func writeFileAtomic(path string, b []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return apperr.Wrap(apperr.Bug, err, "write %s", path)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return apperr.Wrap(apperr.Bug, err, "write %s", path)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return apperr.Wrap(apperr.Bug, err, "write %s", path)
	}
	if err := tmp.Close(); err != nil {
		return apperr.Wrap(apperr.Bug, err, "write %s", path)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return apperr.Wrap(apperr.Bug, err, "write %s", path)
	}
	return nil
}

func writeFindings(w io.Writer, fs []ncf.Finding) error {
	for _, f := range fs {
		where := strings.TrimSpace(f.Alias + " " + f.Entry)
		if where != "" {
			where = " [" + where + "]"
		}
		if _, err := fmt.Fprintf(w, "%s %s%s: %s\n", f.Severity, f.Code, where, f.Message); err != nil {
			return err
		}
	}
	return nil
}

// toProduction is how long an alias took from activation to production, as
// timed at the poll interval, or "-" when it wasn't timed.
func toProduction(a ncf.AliasApply) string {
	if d, ok := a.ToProduction(); ok {
		return d.String()
	}
	return "-"
}
