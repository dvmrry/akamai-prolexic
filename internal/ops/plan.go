package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// PlanDoc is a plan: the diff of the desired file against live.
type PlanDoc struct {
	output.Header
	File string `json:"file"`
	ncf.Plan
	OwnSpaceAnalytics bool `json:"ownSpaceAnalytics" doc:"Whether Prolexic Analytics protected prefixes were part of the own-space check."`

	changesAreDrift bool // the outcome reports changes as drift
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
	// The reviewer sees the removal limit apply will run with: it comes
	// from this plan.
	limit := fmt.Sprintf("%d entries per alias", d.Settings.MaxRemovals)
	if d.Settings.MaxRemovals < 0 {
		limit = "none"
	}
	if _, err := fmt.Fprintf(w, "removal limit: %s\n", limit); err != nil {
		return err
	}
	// A plan with errors can't be applied: printing its digest would only
	// invite copying it.
	if ncf.HasErrors(d.Findings) {
		_, err := fmt.Fprintln(w, "\ndigest: none (the plan has errors; fix them and plan again)")
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

// PlanInput diffs the desired file against live.
type PlanInput struct {
	File string // the desired file's path
	// MaxRemovals is the most entries one alias may lose; -1 for no limit.
	// ncf.DefaultMaxRemovals is the usual value; 0 allows none.
	MaxRemovals int
	// SkipLiveOwnSpace leaves Prolexic Analytics' protected prefixes and own
	// AS numbers out of the own-space checks; the plan records it.
	SkipLiveOwnSpace bool
	// ChangesAreDrift makes changes the outcome, for a scheduled drift check.
	ChangesAreDrift bool
	// Out, if set, is where the plan's JSON is also saved, for Apply and
	// Verify. A symbolic link, a directory or the desired file is refused.
	Out string
}

// Plan reads live state (read credentials only), diffs it against the
// desired file and runs every offline and live check.
func (r *Runtime) Plan(ctx context.Context, in PlanInput) (*PlanDoc, error) {
	if in.MaxRemovals < -1 { // ncf.MakePlan checks too; this is before any read
		return nil, apperr.New(apperr.Usage, "the removal limit must be -1 (no limit) or at least 0, not %d", in.MaxRemovals)
	}
	if in.Out != "" {
		if err := checkOutPath(r.file(in.Out), r.file(in.File)); err != nil {
			return nil, err
		}
	}
	f, raw, err := readDesired(r.file(in.File))
	if err != nil {
		return nil, err
	}
	store, err := r.ncfRead()
	if err != nil {
		return nil, err
	}
	p, err := r.checker().MakePlan(ctx, store, f, raw, r.planOptions(in.MaxRemovals, in.SkipLiveOwnSpace))
	if err != nil {
		return nil, err
	}
	doc := &PlanDoc{File: in.File, Plan: *p, OwnSpaceAnalytics: !in.SkipLiveOwnSpace, changesAreDrift: in.ChangesAreDrift}
	if in.Out != "" {
		if err := r.saveDocument(r.file(in.Out), doc); err != nil {
			return doc, err
		}
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
	fmt.Fprintln(tw, "ALIAS\tID\tSTATUS\tFROM\tVERSION\t+\t-\tTO PRODUCTION")
	for _, al := range d.Result.Aliases {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t%d\t%s\n", al.Name, al.ID, al.Status, dash(al.FromVersion), dash(al.Version), len(al.Add), len(al.Remove), toProduction(al))
	}
	return tw.Flush()
}

// toProduction is how long an alias took from activation to production, as
// timed at the poll interval, or "-" when it wasn't timed.
func toProduction(a ncf.AliasApply) string {
	if d, ok := a.ToProduction(); ok {
		return d.String()
	}
	return "-"
}

// ApplyInput applies a reviewed plan.
type ApplyInput struct {
	File string // the desired file's path
	// Plan is the reviewed plan's path, as Plan saved it. Apply runs the
	// checks it recorded, and refuses it for another file or account.
	Plan     string
	Timeout  time.Duration // how long to wait for production; 0 means ncf.DefaultApplyTimeout
	Interval time.Duration // polling period while waiting; 0 means ncf.DefaultApplyInterval
}

// Apply writes the reviewed plan with the write credentials and waits for
// production to carry the new versions (ncf.Apply has the invariants). Each
// step is reported as progress. Its refusals and failures are errors,
// returned with the document saying what happened.
func (r *Runtime) Apply(ctx context.Context, in ApplyInput) (*ApplyDoc, error) {
	reviewed, err := readPlan(r.file(in.Plan))
	if err != nil {
		return nil, err
	}
	f, raw, err := readDesired(r.file(in.File))
	if err != nil {
		return nil, err
	}
	read, err := r.ncfRead()
	if err != nil {
		return nil, err
	}
	if r.WriteClient == nil {
		return nil, apperr.New(apperr.Credentials, "no write credentials: this front can't apply")
	}
	wc, err := r.WriteClient()
	if err != nil {
		return nil, err
	}
	s := reviewed.Settings
	p, res, err := r.checker().Apply(ctx, read, ncfapi.NewV2(wc), f, raw, ncf.ApplyOptions{
		PlanOptions: r.planOptions(s.MaxRemovals, s.SkipLiveOwnSpace), Reviewed: reviewed, Timeout: in.Timeout, Interval: in.Interval,
		Sleep: r.Sleep, Now: r.Now, Progress: func(p ncf.Progress) { r.progress(p.Message) },
	})
	if p == nil && res == nil {
		return nil, err
	}
	return &ApplyDoc{File: in.File, Plan: p, Result: res}, err
}

// VerifyDoc compares a saved plan's expected end state with a fresh read.
type VerifyDoc struct {
	output.Header
	PlanFile string `json:"planFile"`
	ncf.VerifyResult
}

func (*VerifyDoc) SchemaID() string { return "prolexic.verify.v1" }

func (d *VerifyDoc) Outcome() error {
	if d.Verified {
		return nil
	}
	var off []string
	for _, a := range d.Aliases {
		if !a.Verified {
			off = append(off, a.Name)
		}
	}
	return apperr.New(apperr.Drift, "%d of %d aliases don't match the plan: %s", len(off), len(d.Aliases), strings.Join(off, ", "))
}

func (d *VerifyDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ALIAS\tID\tVERIFIED\tACTIVE\tPRODUCTION\tPROBLEMS")
	for _, a := range d.Aliases {
		fmt.Fprintf(tw, "%s\t%d\t%t\t%s\t%s\t%s\n", a.Name, a.ID, a.Verified, dash(a.ActiveVersion), dash(a.ProdVersion), dash(strings.Join(a.Problems, "; ")))
	}
	return tw.Flush()
}

// VerifyInput names the saved plan to verify.
type VerifyInput struct {
	Plan string // the saved plan's path
}

// Verify reads every alias in a saved plan fresh and checks the plan's end
// state (ncf.Verify). Read-only.
func (r *Runtime) Verify(ctx context.Context, in VerifyInput) (*VerifyDoc, error) {
	p, err := readPlan(r.file(in.Plan))
	if err != nil {
		return nil, err
	}
	store, err := r.ncfRead()
	if err != nil {
		return nil, err
	}
	res, err := ncf.Verify(ctx, store, p)
	if err != nil {
		return nil, err
	}
	return &VerifyDoc{PlanFile: in.Plan, VerifyResult: *res}, nil
}

// ReadPlan reads a plan document that Plan saved, refusing one saved by an
// older prolexic.
func ReadPlan(path string) (*ncf.Plan, error) { return readPlan(file{open: path, show: path}) }

func readPlan(p file) (*ncf.Plan, error) {
	path := p.show
	if p.open == "" {
		return nil, apperr.New(apperr.Usage, "the saved plan's path is required")
	}
	b, err := os.ReadFile(p.open)
	if errors.Is(err, os.ErrNotExist) {
		return nil, apperr.New(apperr.NotFound, "no plan file %s", path)
	}
	if err != nil {
		return nil, apperr.New(apperr.Usage, "read %s: %v", path, fsErr(err))
	}
	var doc struct {
		Schema string `json:"schema"`
		ncf.Plan
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "%s: not a plan document", path)
	}
	if want := (&PlanDoc{}).SchemaID(); doc.Schema != want {
		return nil, apperr.New(apperr.Usage, "%s: schema %q, want %s (save the plan's JSON output)", path, doc.Schema, want)
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(b, &keys) // it decoded above
	if _, ok := keys["settings"]; !ok || doc.Digest == "" || doc.FileDigest == "" {
		return nil, apperr.New(apperr.Usage, "%s was saved by an older prolexic (no settings or digests); plan again and save it", path)
	}
	return &doc.Plan, nil
}
