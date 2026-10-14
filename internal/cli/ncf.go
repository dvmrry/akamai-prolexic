package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
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

func runValidate(_ context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	file := fileFlag(fs)
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	f, raw, err := readDesired(*file)
	if err != nil {
		return nil, err
	}
	doc := &ValidateDoc{File: *file, Findings: nonNil(a.checker().Validate(f, raw))}
	doc.Valid = !ncf.HasErrors(doc.Findings)
	if !doc.Valid {
		return doc, apperr.New(apperr.Validation, "%s has errors", *file)
	}
	return doc, nil
}

// FmtDoc is the result of fmt.
type FmtDoc struct {
	output.Header
	File      string `json:"file"`
	Canonical bool   `json:"canonical" doc:"Whether the file was already canonical."`
	Written   bool   `json:"written"`
}

func (*FmtDoc) SchemaID() string { return "prolexic.fmt.v1" }

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

func runFmt(_ context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	file := fileFlag(fs)
	check := fs.Bool("check", false, "fail if the file isn't canonical; write nothing")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	f, raw, err := readDesired(*file)
	if err != nil {
		return nil, err
	}
	canon, err := ncf.Canonical(f)
	if err != nil {
		return nil, err
	}
	doc := &FmtDoc{File: *file, Canonical: bytes.Equal(raw, canon)}
	switch {
	case doc.Canonical:
		return doc, nil
	case *check:
		return doc, apperr.New(apperr.Validation, "%s is not in canonical form; run prolexic fmt", *file)
	}
	if err := writeFileAtomic(*file, canon); err != nil {
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

func runAdd(_ context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	file := fileFlag(fs)
	ticket := fs.String("ticket", "", "the ticket authorising the change (required)")
	reason := fs.String("reason", "", "why the entries are added (required)")
	expires := fs.String("expires", "", "YYYY-MM-DD after which the entries are flagged as expired")
	pos, err := a.parseInterleaved(fs, args)
	if err != nil {
		return nil, err
	}
	if len(pos) < 2 || *ticket == "" || *reason == "" {
		return nil, apperr.New(apperr.Usage, "usage: prolexic add --file F <alias> <entry>... --ticket T --reason R [--expires YYYY-MM-DD]")
	}
	if *expires != "" {
		if _, err := ncf.ParseDate(*expires); err != nil {
			return nil, apperr.New(apperr.Usage, "--expires %q is not YYYY-MM-DD", *expires)
		}
	}
	f, raw, err := readDesired(*file)
	if err != nil {
		return nil, err
	}
	doc := &ChangeDoc{File: *file, Action: "add", Alias: pos[0], Ticket: *ticket, Entries: []ncf.Entry{}, Findings: []ncf.Finding{}}
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
		e := ncf.Entry{CIDR: key, Ticket: *ticket, Reason: *reason, Added: today, Expires: *expires}
		alias.Entries = append(alias.Entries, e)
		doc.Entries = append(doc.Entries, e)
	}
	return a.commitChange(doc, f, raw, added)
}

func runRemove(_ context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	file := fileFlag(fs)
	ticket := fs.String("ticket", "", "the ticket authorising the change (required)")
	pos, err := a.parseInterleaved(fs, args)
	if err != nil {
		return nil, err
	}
	if len(pos) < 2 || *ticket == "" {
		return nil, apperr.New(apperr.Usage, "usage: prolexic remove --file F <alias> <entry>... --ticket T")
	}
	f, raw, err := readDesired(*file)
	if err != nil {
		return nil, err
	}
	doc := &ChangeDoc{File: *file, Action: "remove", Alias: pos[0], Ticket: *ticket, Entries: []ncf.Entry{}, Findings: []ncf.Finding{}}
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
		return doc, apperr.New(apperr.Validation, "%s: not written", doc.File)
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
}

func (*PlanDoc) SchemaID() string { return "prolexic.plan.v1" }

func (d *PlanDoc) WriteText(w io.Writer) error {
	for _, al := range d.Aliases {
		if !al.Changed() {
			fmt.Fprintf(w, "  %s (%d): no changes\n", al.Name, al.ID)
			continue
		}
		fmt.Fprintf(w, "~ %s (%d) %s %s, activeVersion %s\n", al.Name, al.ID, al.Type, al.IPVersion, dash(al.ActiveVersion))
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
	_, err := fmt.Fprintf(w, "\ndigest: %s\n", d.Digest)
	return err
}

func (a *app) planFlags(fs *flag.FlagSet) (file *string, maxRemovals *int, noAnalytics *bool) {
	file = fileFlag(fs)
	maxRemovals = fs.Int("max-removals", ncf.DefaultMaxRemovals, "most entries one alias may lose in one apply; -1 for no limit")
	noAnalytics = fs.Bool("no-analytics-own-space", false, "skip Prolexic Analytics protected prefixes in the own-space check (recorded in the plan)")
	return
}

func runPlan(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	file, maxRemovals, noAnalytics := a.planFlags(fs)
	exitCode := fs.Bool("exit-code", false, "exit 7 when the plan has changes (drift)")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	f, raw, err := readDesired(*file)
	if err != nil {
		return nil, err
	}
	store, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	opts, warnings := a.planOptions(*maxRemovals, *noAnalytics)
	p, err := a.checker().MakePlan(ctx, store, f, raw, opts)
	if err != nil {
		return nil, err
	}
	p.Findings = append(p.Findings, *warnings...)
	doc := &PlanDoc{File: *file, Plan: *p, OwnSpaceAnalytics: !*noAnalytics}
	switch {
	case ncf.HasErrors(p.Findings):
		return doc, apperr.New(apperr.Validation, "the plan has errors")
	case *exitCode && p.Changes:
		return doc, apperr.New(apperr.Drift, "live differs from %s", *file)
	}
	return doc, nil
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
	fmt.Fprintln(tw, "ALIAS\tID\tSTATUS\tFROM\tVERSION\t+\t-")
	for _, al := range d.Result.Aliases {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t%d\n", al.Name, al.ID, al.Status, dash(al.FromVersion), dash(al.Version), len(al.Add), len(al.Remove))
	}
	return tw.Flush()
}

func runApply(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	file, maxRemovals, noAnalytics := a.planFlags(fs)
	expect := fs.String("expect-digest", "", "the digest of the reviewed plan (required)")
	timeout := fs.Duration("timeout", ncf.DefaultApplyTimeout, "how long to wait for production to carry the new versions")
	interval := fs.Duration("interval", ncf.DefaultApplyInterval, "polling period while waiting")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	if *expect == "" {
		return nil, apperr.New(apperr.Usage, "--expect-digest is required: apply only what was reviewed")
	}
	f, raw, err := readDesired(*file)
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
	opts, warnings := a.planOptions(*maxRemovals, *noAnalytics)
	p, res, err := a.checker().Apply(ctx, read, a.ncfStore(wc), f, raw, ncf.ApplyOptions{
		PlanOptions: opts, ExpectDigest: *expect, Timeout: *timeout, Interval: *interval,
		Sleep: a.env.Sleep, Now: a.env.Now,
	})
	if p != nil {
		p.Findings = append(p.Findings, *warnings...)
	}
	if p == nil && res == nil {
		return nil, err
	}
	return &ApplyDoc{File: *file, Plan: p, Result: res}, err
}

// planOptions builds the plan options; the returned findings collect
// warnings from the Analytics own-space source once the plan has run.
func (a *app) planOptions(maxRemovals int, noAnalytics bool) (ncf.PlanOptions, *[]ncf.Finding) {
	warnings := &[]ncf.Finding{}
	opts := ncf.PlanOptions{MaxRemovals: maxRemovals}
	if noAnalytics {
		*warnings = append(*warnings, ncf.Finding{Severity: ncf.Warning, Code: "own_space_analytics_skipped",
			Message: "--no-analytics-own-space: Prolexic Analytics protected prefixes were not checked"})
		return opts, warnings
	}
	opts.OwnSpace = func(ctx context.Context) ([]ncf.OwnSpacePrefix, error) {
		api, err := a.analytics()
		if err != nil {
			return nil, err
		}
		names, err := analytics.ResolveCustomers(ctx, api, nil)
		if err != nil {
			return nil, err
		}
		// A failed name fails the plan: the own-space check can't be
		// partial.
		sets, _, err := analytics.FanOut(ctx, names, func(ctx context.Context, name string) ([]analytics.MetricTypes, error) {
			m, err := api.MetricTypes(ctx, name)
			return []analytics.MetricTypes{m}, err
		})
		if err != nil {
			return nil, err
		}
		var out []ncf.OwnSpacePrefix
		for _, m := range sets {
			if len(m.Prefixes) == 0 {
				// Empty means unknown, not "nothing protected".
				*warnings = append(*warnings, ncf.Finding{Severity: ncf.Warning, Code: "own_space_analytics_empty",
					Message: fmt.Sprintf("Prolexic Analytics reports no protected prefixes for customer name %s", m.Customer)})
			}
			for _, p := range m.Prefixes {
				out = append(out, ncf.OwnSpacePrefix{Prefix: p, Source: "analytics " + m.Customer + "/" + m.Site})
			}
		}
		return out, nil
	}
	return opts, warnings
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

// ncfStore picks the adapter. Only v1 exists until the NCF v2 spec arrives.
func (a *app) ncfStore(c *akamai.Client) ncf.Store {
	return ncfapi.NewV1(c)
}

func fileFlag(fs *flag.FlagSet) *string {
	return fs.String("file", "", "the desired file (required)")
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

// parseInterleaved parses flags that may come after positional arguments
// (`add --file F alias 192.0.2.1 --ticket T`) and returns the positionals.
func (a *app) parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := a.parse(fs, args, true); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}
