package ncf

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// ApplyOptions tune apply.
type ApplyOptions struct {
	PlanOptions
	// ExpectDigest is the digest of the reviewed plan. Apply refuses if a
	// fresh plan's digest differs.
	ExpectDigest string
	// Timeout bounds the wait for production to carry the new versions.
	Timeout time.Duration
	// Interval is the polling period while waiting.
	Interval time.Duration
	// Progress, if set, hears each step as apply runs (created, activated,
	// waiting, in production), so a front can show that a long wait for
	// production isn't a hang. nil is silent.
	Progress func(Progress)
	// Sleep and Now are injectable for tests; nil means real time.
	Sleep func(context.Context, time.Duration) error
	Now   func() time.Time
}

// Defaults for the deployment wait. Activation takes effect after a
// deployment window of up to about ten minutes.
const (
	DefaultApplyTimeout  = 15 * time.Minute
	DefaultApplyInterval = 15 * time.Second
)

// Status of one alias in an apply.
type Status string

const (
	StatusUnchanged Status = "unchanged" // nothing to do
	StatusSkipped   Status = "skipped"   // not reached: an earlier step failed
	StatusFailed    Status = "failed"
	StatusCreated   Status = "created"  // version created and verified, not active
	StatusActive    Status = "active"   // activated; final for an alias no deployed rule uses
	StatusDeployed  Status = "deployed" // production carries it, no failed rules
	// StatusRolledBack: activated on upload, then the version it replaced
	// was re-activated because the apply failed.
	StatusRolledBack Status = "rolled_back"
)

// ApplyResult reports what apply did, alias by alias.
type ApplyResult struct {
	AccountID      string       `json:"accountId"`
	Digest         string       `json:"digest"`
	AlreadyApplied bool         `json:"alreadyApplied" doc:"Live already matched the file, so nothing was written; apply only waited for production to catch up."`
	Aliases        []AliasApply `json:"aliases"`
}

// AliasApply is one alias's outcome.
type AliasApply struct {
	Name        string  `json:"name"`
	ID          int64   `json:"id"`
	Status      Status  `json:"status" enum:"unchanged,skipped,failed,created,active,deployed,rolled_back"`
	FromVersion string  `json:"fromVersion"`
	Version     string  `json:"version,omitempty" doc:"The version this apply created."`
	Add         []Entry `json:"add"`
	Remove      []Entry `json:"remove"`
	Error       string  `json:"error,omitempty"`
	// WaitedForProduction is set on an unchanged alias whose production
	// lagged its active version (activated earlier or by someone else), which
	// apply waited on without writing it.
	WaitedForProduction bool `json:"waitedForProduction,omitempty" doc:"Unchanged, but production lagged its active version (activated earlier or by someone else), so apply waited on it without writing it."`
	// ActivatedAt and ProductionAt time the change: when this apply activated
	// the version, and the first poll that saw production carry it.
	ActivatedAt  string `json:"activatedAt,omitempty" doc:"When this apply activated the version (RFC 3339; a BIG upload activates on arrival)."`
	ProductionAt string `json:"productionAt,omitempty" doc:"The first poll that saw production carry the version (RFC 3339): accurate to the poll interval."`
}

// Apply re-plans f, refuses if the digest moved, then writes each changed
// alias in three phases:
//
//  1. create: re-read the alias and refuse if its activeVersion (the
//     conflict token) moved; create one version holding the desired
//     entries; re-read it and compare. A version that doesn't match is left
//     inactive. A create that failed ambiguously is never retried: the
//     version list proves whether it landed.
//  2. activate every created version, only once all of them verified.
//  3. wait until production carries every new version and the ACL
//     deployment shows no failed rules, or the timeout passes.
//
// read serves the plan and every read; write only creates and activates.
func (c *Checker) Apply(ctx context.Context, read, write Store, f *File, raw []byte, opts ApplyOptions) (*Plan, *ApplyResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultApplyTimeout
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultApplyInterval
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepCtx
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	plan, err := c.MakePlan(ctx, read, f, raw, opts.PlanOptions)
	if err != nil {
		return nil, nil, err
	}
	if HasErrors(plan.Findings) {
		return plan, nil, apperr.New(apperr.Validation, "the plan has errors; nothing applied")
	}
	// The digest guards every write (invariant 1). With nothing to write,
	// live already matches the reviewed file (a re-run after success):
	// converge on production and succeed whatever the digest.
	if plan.Changes && plan.Digest != opts.ExpectDigest {
		return plan, nil, apperr.New(apperr.Drift, "the plan digest moved (reviewed %s, now %s); nothing applied: re-plan and review", opts.ExpectDigest, plan.Digest)
	}

	r := newApplyRun(c, read, write, plan, opts)
	if err := r.create(ctx); err != nil {
		return plan, r.res, err
	}
	if err := r.activate(ctx); err != nil {
		return plan, r.res, err
	}
	return plan, r.res, r.waitForProduction(ctx)
}

// applyRun is one apply's state across its phases: the plan, the result
// being built, and todo, the changed aliases (indexes into both) in write
// order.
type applyRun struct {
	c           *Checker
	read, write Store
	plan        *Plan
	res         *ApplyResult
	todo        []int
	opts        ApplyOptions
	comment     string // every version this apply creates carries it
}

func newApplyRun(c *Checker, read, write Store, plan *Plan, opts ApplyOptions) *applyRun {
	r := &applyRun{
		c: c, read: read, write: write, plan: plan, opts: opts,
		res:     &ApplyResult{AccountID: plan.AccountID, Digest: plan.Digest, AlreadyApplied: !plan.Changes, Aliases: make([]AliasApply, len(plan.Aliases))},
		comment: "prolexic apply " + plan.Digest,
	}
	for i, ap := range plan.Aliases {
		r.res.Aliases[i] = AliasApply{Name: ap.Name, ID: ap.ID, Status: StatusUnchanged, FromVersion: ap.ActiveVersion, Add: ap.Add, Remove: ap.Remove}
		if ap.Changed() {
			r.res.Aliases[i].Status = StatusSkipped
			r.todo = append(r.todo, i)
		}
	}
	// BIG aliases go last: their upload may activate on arrival, so every
	// other alias should have verified before one is created.
	slices.SortStableFunc(r.todo, func(x, y int) int {
		return cmp.Compare(boolInt(plan.Aliases[x].Type == "BIG"), boolInt(plan.Aliases[y].Type == "BIG"))
	})
	return r
}

// fail marks alias i failed with err and returns err.
func (r *applyRun) fail(i int, err error) error {
	r.res.Aliases[i].Status = StatusFailed
	r.res.Aliases[i].Error = err.Error()
	return err
}

// failAndRollBack puts back everything this apply made live (invariant 3),
// then marks alias i failed.
func (r *applyRun) failAndRollBack(ctx context.Context, i int, err error) error {
	if rerr := rollBack(ctx, r.read, r.write, r.plan, r.res, r.todo); rerr != nil {
		err = fmt.Errorf("%w; and rolling back: %v", err, rerr)
	}
	return r.fail(i, err)
}

// create is phase 1: create and verify each changed alias's version
// (invariants 2 and 4). A failure rolls back every version this apply already
// saw go live on upload.
func (r *applyRun) create(ctx context.Context) error {
	for _, i := range r.todo {
		v, active, err := r.c.createVerified(ctx, r.read, r.write, r.plan.Aliases[i], r.comment)
		r.res.Aliases[i].Version = v
		if err != nil {
			err = r.failAndRollBack(ctx, i, err)
			var rb *rolledBack
			if errors.As(err, &rb) {
				r.res.Aliases[i].Status = StatusRolledBack // its own upload was put back
			}
			return err
		}
		r.res.Aliases[i].Status = StatusCreated
		if active {
			r.res.Aliases[i].Status = StatusActive
			r.res.Aliases[i].ActivatedAt = r.stamp()
			r.progress("activated", i, "created and verified %s %s; a BIG upload activates on arrival", r.res.Aliases[i].Name, v)
			continue
		}
		r.progress("created", i, "created and verified %s %s", r.res.Aliases[i].Name, v)
	}
	return nil
}

// activate is phase 2: activate every created version, re-reading each
// alias's token first (invariant 3). A failure rolls back every alias this
// apply already activated, so the reviewed change lands whole or not at all.
func (r *applyRun) activate(ctx context.Context) error {
	for _, i := range r.todo {
		a, planned := &r.res.Aliases[i], r.plan.Aliases[i].ActiveVersion
		if a.Status == StatusActive {
			continue // the API activated it on creation (BIG upload)
		}
		// No ETag: re-read the token right before activating, so another
		// writer's activation during phase 1 is never silently replaced.
		if cur, err := activeVersion(ctx, r.read, a.ID); err != nil {
			return r.failAndRollBack(ctx, i, apperr.Wrap(apperr.KindOf(err), err, "re-read %s before activating", a.Name))
		} else if cur != planned {
			return r.failAndRollBack(ctx, i, apperr.New(apperr.Conflict, "%s changed during this apply (activeVersion %q, now %q); its version %s was left inactive; re-plan", a.Name, planned, cur, a.Version))
		}
		if err := r.write.Activate(ctx, a.ID, a.Version); err != nil {
			if !ambiguous(err) {
				return r.failAndRollBack(ctx, i, apperr.Wrap(apperr.KindOf(err), err, "activate %s version %s", a.Name, a.Version))
			}
			cur, rerr := activeVersion(context.WithoutCancel(ctx), r.read, a.ID)
			if rerr != nil || cur != a.Version {
				// It may have landed: count it as live so the rollback covers
				// it (re-activating the replaced version is harmless if not).
				a.Status = StatusActive
				return r.failAndRollBack(ctx, i, apperr.Wrap(apperr.Upstream, err, "activate %s version %s: unknown whether it took effect", a.Name, a.Version))
			}
		}
		a.Status = StatusActive
		a.ActivatedAt = r.stamp()
		r.progress("activated", i, "activated %s %s", a.Name, a.Version)
	}
	return nil
}

// targets are the aliases phase 3 waits on, with the version production must
// carry: the new version for a changed alias, and the active version for an
// unchanged one whose production lags (so a re-run after a timed-out apply
// finishes the job). A changed alias a deployed rule uses is always a
// target, for the deployment health check. An alias no deployed rule
// references has nothing to wait for: activation is its end state.
func (r *applyRun) targets() map[int]string {
	target := map[int]string{}
	for i, ap := range r.plan.Aliases {
		want := ap.ActiveVersion
		if ap.Changed() {
			want = r.res.Aliases[i].Version
		}
		if ap.ProdVersion != "" && (ap.Changed() || ap.ProdVersion != want) {
			target[i] = want
		}
	}
	for i := range target {
		if !r.plan.Aliases[i].Changed() {
			r.res.Aliases[i].WaitedForProduction = true
		}
	}
	return target
}

// waitForProduction is phase 3 (invariant 6): poll until production carries
// every target and the ACL deployment is healthy and settled, or the timeout
// passes.
func (r *applyRun) waitForProduction(ctx context.Context) error {
	target := r.targets()
	if len(target) == 0 {
		return nil
	}
	start := r.opts.Now()
	deadline := start.Add(r.opts.Timeout)
	elapsed := func() string {
		return r.opts.Now().Sub(start).Round(time.Second).String() + " of " + r.opts.Timeout.String()
	}
	for {
		// One alias list per poll: it carries every production version and
		// no entries, so a BIG alias isn't re-downloaded every interval.
		all, err := r.read.ListAliases(ctx)
		if err != nil {
			return apperr.Wrap(apperr.KindOf(err), err, "poll aliases")
		}
		prods := make(map[int64]string, len(all))
		for _, l := range all {
			prods[l.ID] = l.ProdVersion
		}
		var pending []string
		for _, i := range slices.Sorted(maps.Keys(target)) { // in plan order: stable progress
			want := target[i]
			prod, ok := prods[r.res.Aliases[i].ID]
			if !ok {
				err := apperr.New(apperr.Upstream, "poll %s: the alias is no longer listed", r.res.Aliases[i].Name)
				if !r.plan.Aliases[i].Changed() {
					return err // never written by this apply: not its failure
				}
				return r.fail(i, err)
			}
			if prod == "" {
				delete(target, i) // no deployed rule uses it any more: nothing to wait for
				continue
			}
			if prod != want {
				pending = append(pending, fmt.Sprintf("%s at %s, want %s", r.res.Aliases[i].Name, prod, want))
			} else if a := &r.res.Aliases[i]; r.plan.Aliases[i].Changed() && a.ProductionAt == "" {
				a.ProductionAt = r.stamp()
				r.progress("in_production", i, "in production: %s %s%s", a.Name, want, sinceActivation(a))
			}
		}
		slices.Sort(pending)
		if len(pending) > 0 {
			r.progress("waiting", -1, "waiting for production: %d of %d aliases (%s), %s", len(target)-len(pending), len(target), strings.Join(pending, "; "), elapsed())
		}
		if len(pending) == 0 {
			d, err := r.read.Deployment(ctx)
			if err != nil {
				return apperr.Wrap(apperr.KindOf(err), err, "read ACL deployment status")
			}
			if why := d.Failure(); why != "" {
				return apperr.New(apperr.Upstream, "production carries the target versions but the ACL deployment is unhealthy: %s", why)
			}
			if !d.Processing {
				for i := range target {
					if r.plan.Aliases[i].Changed() {
						r.res.Aliases[i].Status = StatusDeployed
					}
				}
				return nil
			}
			r.progress("settling", -1, "every alias is in production; the ACL deployment is still processing, %s", elapsed())
		}
		if !r.opts.Now().Before(deadline) {
			return r.timeoutError(ctx, target, prods)
		}
		if err := r.opts.Sleep(ctx, r.opts.Interval); err != nil {
			return err
		}
	}
}

// timeoutError says what is actually lagging when the production wait gives
// up: what this apply wrote, what it only waited on, or the deployment itself.
func (r *applyRun) timeoutError(ctx context.Context, target map[int]string, prods map[int64]string) error {
	timeout := r.opts.Timeout
	written, outside := lagging(r.plan, target, prods, r.res)
	if len(written)+len(outside) > 0 {
		if d, err := r.read.Deployment(ctx); err == nil {
			if why := d.Failure(); why != "" {
				return apperr.New(apperr.Upstream, "not deployed after %s, and the ACL deployment is unhealthy: %s", timeout, why)
			}
		}
	}
	switch {
	case len(written) == 0 && len(outside) == 0:
		return apperr.New(apperr.Upstream, "production carries the target versions, but the ACL deployment is still processing after %s; re-run apply to keep waiting", timeout)
	case !r.plan.Changes:
		return apperr.New(apperr.Upstream, "production still lags after %s for %s, activated outside this apply; this apply wrote nothing", timeout, strings.Join(outside, ", "))
	case len(written) == 0:
		return apperr.New(apperr.Upstream, "this apply's new versions are in production, but after %s production still lags for %s, activated outside this apply", timeout, strings.Join(outside, ", "))
	case len(outside) == 0:
		return apperr.New(apperr.Upstream, "not deployed after %s: %s; the new versions are active and production should follow; re-run apply to keep waiting", timeout, strings.Join(written, ", "))
	default:
		return apperr.New(apperr.Upstream, "not deployed after %s: %s (written by this apply) and %s (activated outside it); re-run apply to keep waiting", timeout, strings.Join(written, ", "), strings.Join(outside, ", "))
	}
}

// createVerified creates ap's version and proves it holds exactly the
// desired entries. It reports whether the API activated the version on
// creation (a BIG upload may); such a version that fails verification is
// rolled back by re-activating the version it replaced.
func (c *Checker) createVerified(ctx context.Context, read, write Store, ap AliasPlan, comment string) (string, bool, error) {
	cur, err := read.GetAlias(ctx, ap.ID)
	if err != nil {
		return "", false, apperr.Wrap(apperr.KindOf(err), err, "re-read %s", ap.Name)
	}
	if cur.ActiveVersion != ap.ActiveVersion {
		return "", false, apperr.New(apperr.Conflict, "%s changed since the plan (activeVersion %q, now %q); re-plan", ap.Name, ap.ActiveVersion, cur.ActiveVersion)
	}
	before, err := read.ListVersions(ctx, ap.ID)
	if err != nil {
		return "", false, apperr.Wrap(apperr.KindOf(err), err, "list versions of %s", ap.Name)
	}

	// A retry of this same reviewed apply re-uses the inactive version an
	// earlier attempt created (same digest comment, same source version)
	// instead of creating another. Its entries are verified like a new one.
	for _, old := range before {
		if old.Active || old.Comment != comment || old.Source != ap.ActiveVersion {
			continue
		}
		if got, err := read.GetVersion(ctx, ap.ID, old.Version); err == nil && SameEntries(got.Entries, ap.desired) {
			return old.Version, false, nil
		}
	}

	created, err := write.CreateVersion(ctx, cur, ap.desired, comment)
	if err != nil {
		if !ambiguous(err) {
			return "", false, apperr.Wrap(apperr.KindOf(err), err, "create a version of %s", ap.Name)
		}
		// Prove the outcome from the version list; never re-send.
		created, err = landed(context.WithoutCancel(ctx), read, ap, before, comment, err)
		if err != nil {
			return "", false, err
		}
	}
	v := created.Version

	got, err := read.GetVersion(ctx, ap.ID, v)
	if err == nil && SameEntries(got.Entries, ap.desired) {
		return v, created.Active || got.Active, nil
	}
	// A BIG upload may go live on arrival; when that can't be confirmed either
	// way, treat it as live, so a failure puts the replaced version back.
	live := created.Active || (err == nil && got.Active) || (err != nil && ap.Type == "BIG")
	if !live {
		if err != nil {
			return v, false, apperr.Wrap(apperr.KindOf(err), err, "re-read %s version %s; it was left inactive", ap.Name, v)
		}
		return v, false, apperr.New(apperr.Upstream, "%s version %s doesn't hold the desired entries; it was left inactive", ap.Name, v)
	}
	// Live on creation and unverified (wrong, or unreadable): put back what
	// was live.
	why := "doesn't hold the desired entries"
	if err != nil {
		why = fmt.Sprintf("couldn't be re-read to verify (%v)", err)
	}
	if rerr := write.Activate(context.WithoutCancel(ctx), ap.ID, ap.ActiveVersion); rerr != nil {
		return v, true, apperr.New(apperr.Upstream, "%s version %s was activated on upload and %s, and re-activating %s failed (%v): fix it by hand", ap.Name, v, why, ap.ActiveVersion, rerr)
	}
	return v, false, &rolledBack{apperr.New(apperr.Upstream, "%s version %s was activated on upload and %s; %s was re-activated", ap.Name, v, why, ap.ActiveVersion)}
}

// lagging names the targeted aliases production hasn't caught up with,
// split into those this apply wrote and those it only waited on, sorted.
func lagging(plan *Plan, target map[int]string, prods map[int64]string, res *ApplyResult) (written, outside []string) {
	for i, want := range target {
		if prods[res.Aliases[i].ID] == want {
			continue
		}
		if plan.Aliases[i].Changed() {
			written = append(written, plan.Aliases[i].Name)
		} else {
			outside = append(outside, plan.Aliases[i].Name)
		}
	}
	slices.Sort(written)
	slices.Sort(outside)
	return written, outside
}

// rolledBack marks an error after which the failing alias's own upload
// was put back, so its status is rolled_back rather than failed.
type rolledBack struct{ error }

func (r *rolledBack) Unwrap() error { return r.error }

// rollBack re-activates the replaced version of every alias this apply made
// live (or may have): BIG uploads that went live on arrival, activations in
// phase 2, and activations whose outcome is unknown. It leaves an alias alone
// if someone else has activated another version since, tries them all, and
// names the ones it couldn't put back.
func rollBack(ctx context.Context, read, write Store, plan *Plan, res *ApplyResult, todo []int) error {
	var failed []string
	for _, j := range todo {
		a := &res.Aliases[j]
		if a.Status != StatusActive {
			continue
		}
		prev := plan.Aliases[j].ActiveVersion
		// Put back only what this apply replaced: if someone else has
		// activated another version since, leave theirs alone.
		cur, err := activeVersion(context.WithoutCancel(ctx), read, a.ID)
		if err == nil && cur == prev {
			a.Status = StatusRolledBack // already back (or never left)
			continue
		}
		if err == nil && cur != a.Version {
			a.Error = fmt.Sprintf("not rolled back: %s is now active, activated by someone else", cur)
			failed = append(failed, a.Name)
			continue
		}
		if err := write.Activate(context.WithoutCancel(ctx), a.ID, prev); err != nil {
			a.Error = fmt.Sprintf("activated on upload; re-activating %s failed: %v", prev, err)
			failed = append(failed, a.Name)
			continue
		}
		a.Status = StatusRolledBack
	}
	if len(failed) > 0 {
		return fmt.Errorf("%s not rolled back; check each alias by hand", strings.Join(failed, ", "))
	}
	return nil
}

// activeVersion reads one alias's active version from the alias list (no
// entries): the cheap token re-check before a write.
func activeVersion(ctx context.Context, read Store, id int64) (string, error) {
	all, err := read.ListAliases(ctx)
	if err != nil {
		return "", err
	}
	for _, l := range all {
		if l.ID == id {
			return l.ActiveVersion, nil
		}
	}
	return "", apperr.New(apperr.NotFound, "alias %d is no longer listed", id)
}

// landed decides an ambiguous create: exactly one new version means it
// landed (verification follows); none means it didn't; more means someone
// else is writing.
func landed(ctx context.Context, read Store, ap AliasPlan, before []AliasVersion, comment string, cause error) (AliasVersion, error) {
	after, err := read.ListVersions(ctx, ap.ID)
	if err != nil {
		return AliasVersion{}, apperr.Wrap(apperr.Upstream, cause, "create a version of %s: unknown whether it landed, and listing versions failed (%v); check status before re-running", ap.Name, err)
	}
	seen := map[string]bool{}
	for _, v := range before {
		seen[v.Version] = true
	}
	var fresh []AliasVersion
	for _, v := range after {
		if !seen[v.Version] {
			fresh = append(fresh, v)
		}
	}
	switch len(fresh) {
	case 0:
		return AliasVersion{}, apperr.Wrap(apperr.Upstream, cause, "create a version of %s: it did not land; safe to re-run", ap.Name)
	case 1:
		// A SOURCE or DIPA version we created carries our comment and source;
		// one that doesn't is another writer's. BIG uploads carry no marker,
		// so for them entry verification is the only check.
		if v := fresh[0]; ap.Type != "BIG" && (v.Comment != comment || v.Source != ap.ActiveVersion) {
			return AliasVersion{}, apperr.New(apperr.Conflict, "create a version of %s: unknown whether it landed, and the one new version (%s) isn't this apply's; someone else is writing", ap.Name, v.Version)
		}
		return fresh[0], nil
	default:
		return AliasVersion{}, apperr.New(apperr.Conflict, "create a version of %s: %d new versions appeared; someone else is writing", ap.Name, len(fresh))
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ambiguous(err error) bool {
	d := apperr.UpstreamOf(err)
	return d != nil && d.Ambiguous
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// stamp is the current time as the result records it.
func (r *applyRun) stamp() string { return r.opts.Now().UTC().Format(time.RFC3339) }

// Progress is one step of an apply, for a front to show while it runs.
type Progress struct {
	Step    string // created, activated, waiting, in_production, settling
	Alias   string // empty for steps about every alias
	Message string // the step in words
}

func (r *applyRun) progress(step string, i int, format string, args ...any) {
	if r.opts.Progress == nil {
		return
	}
	p := Progress{Step: step, Message: fmt.Sprintf(format, args...)}
	if i >= 0 {
		p.Alias = r.res.Aliases[i].Name
	}
	r.opts.Progress(p)
}

// ToProduction is how long the alias took from activation to production,
// accurate to the poll interval; false when this apply didn't time it.
func (a AliasApply) ToProduction() (time.Duration, bool) {
	act, err1 := time.Parse(time.RFC3339, a.ActivatedAt)
	prod, err2 := time.Parse(time.RFC3339, a.ProductionAt)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return prod.Sub(act), true
}

// sinceActivation is " after <duration>" for an alias this apply timed.
func sinceActivation(a *AliasApply) string {
	if d, ok := a.ToProduction(); ok {
		return " after " + d.String()
	}
	return ""
}
