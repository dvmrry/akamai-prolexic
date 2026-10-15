package ncf

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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
	// The digest guards every write. With nothing to write, live already
	// matches the reviewed file (a re-run after success): converge on
	// production and succeed whatever the digest.
	if plan.Changes && plan.Digest != opts.ExpectDigest {
		return plan, nil, apperr.New(apperr.Drift, "the plan digest moved (reviewed %s, now %s); nothing applied: re-plan and review", opts.ExpectDigest, plan.Digest)
	}

	res := &ApplyResult{Digest: plan.Digest, AlreadyApplied: !plan.Changes, Aliases: make([]AliasApply, len(plan.Aliases))}
	var todo []int
	for i, ap := range plan.Aliases {
		res.Aliases[i] = AliasApply{Name: ap.Name, ID: ap.ID, Status: StatusUnchanged, FromVersion: ap.ActiveVersion, Add: ap.Add, Remove: ap.Remove}
		if ap.Changed() {
			res.Aliases[i].Status = StatusSkipped
			todo = append(todo, i)
		}
	}
	fail := func(i int, err error) (*Plan, *ApplyResult, error) {
		res.Aliases[i].Status = StatusFailed
		res.Aliases[i].Error = err.Error()
		return plan, res, err
	}

	// BIG aliases go last: their upload may activate on arrival, so every
	// other alias should have verified before one is created.
	slices.SortStableFunc(todo, func(x, y int) int {
		return cmp.Compare(boolInt(plan.Aliases[x].Type == "BIG"), boolInt(plan.Aliases[y].Type == "BIG"))
	})
	comment := "prolexic apply " + plan.Digest

	// Phase 1: create and verify. A failure rolls back every version this
	// apply already saw go live on upload, so nothing stays active unless
	// everything verified.
	for _, i := range todo {
		ap := plan.Aliases[i]
		v, active, err := c.createVerified(ctx, read, write, ap, comment)
		res.Aliases[i].Version = v
		if err != nil {
			if rerr := rollBack(ctx, read, write, plan, res, todo); rerr != nil {
				err = fmt.Errorf("%w; and rolling back: %v", err, rerr)
			}
			p, r, ferr := fail(i, err)
			var rb *rolledBack
			if errors.As(err, &rb) {
				r.Aliases[i].Status = StatusRolledBack // its own upload was put back
			}
			return p, r, ferr
		}
		res.Aliases[i].Status = StatusCreated
		if active {
			res.Aliases[i].Status = StatusActive
		}
	}

	// Phase 2: activate. A failure rolls back every alias this apply already
	// activated, so the reviewed change lands whole or not at all.
	failActivate := func(i int, err error) (*Plan, *ApplyResult, error) {
		if rerr := rollBack(ctx, read, write, plan, res, todo); rerr != nil {
			err = fmt.Errorf("%w; and rolling back: %v", err, rerr)
		}
		return fail(i, err)
	}
	for _, i := range todo {
		a := &res.Aliases[i]
		if a.Status == StatusActive {
			continue // the API activated it on creation (BIG upload)
		}
		// No ETag: re-read the token right before activating, so another
		// writer's activation during phase 1 is never silently replaced.
		if cur, err := activeVersion(ctx, read, a.ID); err != nil {
			return failActivate(i, apperr.Wrap(apperr.CodeOf(err), err, "re-read %s before activating", a.Name))
		} else if cur != plan.Aliases[i].ActiveVersion {
			return failActivate(i, apperr.New(apperr.Conflict, "%s changed during this apply (activeVersion %q, now %q); its version %s was left inactive; re-plan", a.Name, plan.Aliases[i].ActiveVersion, cur, a.Version))
		}
		if err := write.Activate(ctx, a.ID, a.Version); err != nil {
			if !ambiguous(err) {
				return failActivate(i, apperr.Wrap(apperr.CodeOf(err), err, "activate %s version %s", a.Name, a.Version))
			}
			cur, rerr := activeVersion(context.WithoutCancel(ctx), read, a.ID)
			if rerr != nil || cur != a.Version {
				// It may have landed: count it as live so the rollback covers
				// it (re-activating the replaced version is harmless if not).
				a.Status = StatusActive
				return failActivate(i, apperr.Wrap(apperr.Upstream, err, "activate %s version %s: unknown whether it took effect", a.Name, a.Version))
			}
		}
		a.Status = StatusActive
	}

	// Phase 3: wait until production carries each alias's target: the new
	// version for a changed alias, and the active version for an unchanged
	// one whose production lags, so a re-run after a timed-out apply
	// finishes the job. An alias no deployed rule references has nothing to
	// wait for: activation is its end state.
	target := map[int]string{}
	for i, ap := range plan.Aliases {
		want := ap.ActiveVersion
		if ap.Changed() {
			want = res.Aliases[i].Version
		}
		// A changed alias a deployed rule uses always gets the deployment
		// health check, even if production already carries its version.
		if ap.ProdVersion != "" && (ap.Changed() || ap.ProdVersion != want) {
			target[i] = want
		}
	}
	if len(target) == 0 {
		return plan, res, nil
	}
	for i := range target {
		if !plan.Aliases[i].Changed() {
			res.Aliases[i].WaitedForProduction = true
		}
	}
	deadline := opts.Now().Add(opts.Timeout)
	for {
		// One alias list per poll: it carries every production version and
		// no entries, so a BIG alias isn't re-downloaded every interval.
		all, err := read.ListAliases(ctx)
		if err != nil {
			return plan, res, apperr.Wrap(apperr.CodeOf(err), err, "poll aliases")
		}
		prods := make(map[int64]string, len(all))
		for _, l := range all {
			prods[l.ID] = l.ProdVersion
		}
		pending := 0
		for i, want := range target {
			prod, ok := prods[res.Aliases[i].ID]
			if !ok {
				err := apperr.New(apperr.Upstream, "poll %s: the alias is no longer listed", res.Aliases[i].Name)
				if !plan.Aliases[i].Changed() {
					return plan, res, err // never written by this apply: not its failure
				}
				return fail(i, err)
			}
			if prod == "" {
				delete(target, i) // no deployed rule uses it any more: nothing to wait for
				continue
			}
			if prod != want {
				pending++
			}
		}
		if pending == 0 {
			d, err := read.Deployment(ctx)
			if err != nil {
				return plan, res, apperr.Wrap(apperr.CodeOf(err), err, "read ACL deployment status")
			}
			if why := d.Failure(); why != "" {
				return plan, res, apperr.New(apperr.Upstream, "production carries the target versions but the ACL deployment is unhealthy: %s", why)
			}
			if !d.Processing {
				for i := range target {
					if plan.Aliases[i].Changed() {
						res.Aliases[i].Status = StatusDeployed
					}
				}
				return plan, res, nil
			}
		}
		if !opts.Now().Before(deadline) {
			written, outside := lagging(plan, target, prods, res)
			if len(written)+len(outside) > 0 {
				// Say what the deployment itself reports, if it's part of it.
				if d, derr := read.Deployment(ctx); derr == nil {
					if why := d.Failure(); why != "" {
						return plan, res, apperr.New(apperr.Upstream, "not deployed after %s, and the ACL deployment is unhealthy: %s", opts.Timeout, why)
					}
				}
			}
			switch {
			case len(written) == 0 && len(outside) == 0:
				return plan, res, apperr.New(apperr.Upstream, "production carries the target versions, but the ACL deployment is still processing after %s; re-run apply to keep waiting", opts.Timeout)
			case !plan.Changes:
				return plan, res, apperr.New(apperr.Upstream, "production still lags after %s for %s, activated outside this apply; this apply wrote nothing", opts.Timeout, strings.Join(outside, ", "))
			case len(written) == 0:
				return plan, res, apperr.New(apperr.Upstream, "this apply's new versions are in production, but after %s production still lags for %s, activated outside this apply", opts.Timeout, strings.Join(outside, ", "))
			case len(outside) == 0:
				return plan, res, apperr.New(apperr.Upstream, "not deployed after %s: %s; the new versions are active and production should follow; re-run apply to keep waiting", opts.Timeout, strings.Join(written, ", "))
			default:
				return plan, res, apperr.New(apperr.Upstream, "not deployed after %s: %s (written by this apply) and %s (activated outside it); re-run apply to keep waiting", opts.Timeout, strings.Join(written, ", "), strings.Join(outside, ", "))
			}
		}
		if err := opts.Sleep(ctx, opts.Interval); err != nil {
			return plan, res, err
		}
	}
}

// createVerified creates ap's version and proves it holds exactly the
// desired entries. It reports whether the API activated the version on
// creation (a BIG upload may); such a version that fails verification is
// rolled back by re-activating the version it replaced.
func (c *Checker) createVerified(ctx context.Context, read, write Store, ap AliasPlan, comment string) (string, bool, error) {
	cur, err := read.GetAlias(ctx, ap.ID)
	if err != nil {
		return "", false, apperr.Wrap(apperr.CodeOf(err), err, "re-read %s", ap.Name)
	}
	if cur.ActiveVersion != ap.ActiveVersion {
		return "", false, apperr.New(apperr.Conflict, "%s changed since the plan (activeVersion %q, now %q); re-plan", ap.Name, ap.ActiveVersion, cur.ActiveVersion)
	}
	before, err := read.ListVersions(ctx, ap.ID)
	if err != nil {
		return "", false, apperr.Wrap(apperr.CodeOf(err), err, "list versions of %s", ap.Name)
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
			return "", false, apperr.Wrap(apperr.CodeOf(err), err, "create a version of %s", ap.Name)
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
			return v, false, apperr.Wrap(apperr.CodeOf(err), err, "re-read %s version %s; it was left inactive", ap.Name, v)
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

// rollBack re-activates the replaced version of every alias that went live
// on upload during this apply's create phase. It tries them all and names
// the ones it couldn't put back.
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
