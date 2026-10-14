package ncf

import (
	"context"
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
	StatusActive    Status = "active"   // activated, production not yet carrying it
	StatusDeployed  Status = "deployed" // production carries it, no failed rules
)

// ApplyResult reports what apply did, alias by alias.
type ApplyResult struct {
	Digest  string       `json:"digest"`
	Aliases []AliasApply `json:"aliases"`
}

// AliasApply is one alias's outcome.
type AliasApply struct {
	Name        string  `json:"name"`
	ID          int64   `json:"id"`
	Status      Status  `json:"status" enum:"unchanged,skipped,failed,created,active,deployed"`
	FromVersion string  `json:"fromVersion"`
	Version     string  `json:"version,omitempty" doc:"The version this apply created."`
	Add         []Entry `json:"add"`
	Remove      []Entry `json:"remove"`
	Error       string  `json:"error,omitempty"`
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
	if plan.Digest != opts.ExpectDigest {
		return plan, nil, apperr.New(apperr.Drift, "the plan digest moved (reviewed %s, now %s); nothing applied: re-plan and review", opts.ExpectDigest, plan.Digest)
	}

	res := &ApplyResult{Digest: plan.Digest, Aliases: make([]AliasApply, len(plan.Aliases))}
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

	// Phase 1: create and verify.
	for _, i := range todo {
		ap := plan.Aliases[i]
		v, err := c.createVerified(ctx, read, write, ap)
		if err != nil {
			return fail(i, err)
		}
		res.Aliases[i].Version, res.Aliases[i].Status = v, StatusCreated
	}

	// Phase 2: activate.
	for _, i := range todo {
		a := &res.Aliases[i]
		if err := write.Activate(ctx, a.ID, a.Version); err != nil {
			if !ambiguous(err) {
				return fail(i, apperr.Wrap(apperr.CodeOf(err), err, "activate %s version %s", a.Name, a.Version))
			}
			cur, rerr := read.GetAlias(context.WithoutCancel(ctx), a.ID)
			if rerr != nil || cur.ActiveVersion != a.Version {
				return fail(i, apperr.Wrap(apperr.Upstream, err, "activate %s version %s: unknown whether it took effect; check status before re-running", a.Name, a.Version))
			}
		}
		a.Status = StatusActive
	}

	// Phase 3: wait for production.
	deadline := opts.Now().Add(opts.Timeout)
	for {
		pending := 0
		for _, i := range todo {
			a := &res.Aliases[i]
			if a.Status == StatusDeployed {
				continue
			}
			cur, err := read.GetAlias(ctx, a.ID)
			if err != nil {
				return fail(i, apperr.Wrap(apperr.CodeOf(err), err, "poll %s", a.Name))
			}
			if cur.ProdVersion == a.Version {
				a.Status = StatusDeployed // provisional: confirmed by the deployment check below
			} else {
				pending++
			}
		}
		if pending == 0 {
			d, err := read.Deployment(ctx)
			if err != nil {
				return plan, res, apperr.Wrap(apperr.CodeOf(err), err, "read ACL deployment status")
			}
			if why := d.Failure(); why != "" {
				for _, i := range todo {
					res.Aliases[i].Status = StatusActive
				}
				return plan, res, apperr.New(apperr.Upstream, "production carries the new versions but the ACL deployment is unhealthy: %s", why)
			}
			if !d.Processing {
				return plan, res, nil
			}
			for _, i := range todo {
				res.Aliases[i].Status = StatusActive
			}
		}
		if !opts.Now().Before(deadline) {
			return plan, res, apperr.New(apperr.Upstream, "not deployed after %s; the new versions are active and production should follow; check status", opts.Timeout)
		}
		if err := opts.Sleep(ctx, opts.Interval); err != nil {
			return plan, res, err
		}
	}
}

// createVerified creates ap's version and proves it holds exactly the
// desired entries.
func (c *Checker) createVerified(ctx context.Context, read, write Store, ap AliasPlan) (string, error) {
	cur, err := read.GetAlias(ctx, ap.ID)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeOf(err), err, "re-read %s", ap.Name)
	}
	if cur.ActiveVersion != ap.ActiveVersion {
		return "", apperr.New(apperr.Conflict, "%s changed since the plan (activeVersion %q, now %q); re-plan", ap.Name, ap.ActiveVersion, cur.ActiveVersion)
	}
	before, err := read.ListVersions(ctx, ap.ID)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeOf(err), err, "list versions of %s", ap.Name)
	}

	v, err := write.CreateVersion(ctx, cur, ap.desired)
	if err != nil {
		if !ambiguous(err) {
			return "", apperr.Wrap(apperr.CodeOf(err), err, "create a version of %s", ap.Name)
		}
		// Prove the outcome from the version list; never re-send.
		v, err = landed(context.WithoutCancel(ctx), read, ap, before, err)
		if err != nil {
			return "", err
		}
	}

	got, err := read.GetVersion(ctx, ap.ID, v)
	if err != nil {
		return v, apperr.Wrap(apperr.CodeOf(err), err, "re-read %s version %s", ap.Name, v)
	}
	if !SameEntries(got.Entries, ap.desired) {
		return v, apperr.New(apperr.Upstream, "%s version %s doesn't hold the desired entries; it was left inactive", ap.Name, v)
	}
	return v, nil
}

// landed decides an ambiguous create: exactly one new version means it
// landed (verification follows); none means it didn't; more means someone
// else is writing.
func landed(ctx context.Context, read Store, ap AliasPlan, before []AliasVersion, cause error) (string, error) {
	after, err := read.ListVersions(ctx, ap.ID)
	if err != nil {
		return "", apperr.Wrap(apperr.Upstream, cause, "create a version of %s: unknown whether it landed, and listing versions failed (%v); check status before re-running", ap.Name, err)
	}
	seen := map[string]bool{}
	for _, v := range before {
		seen[v.Version] = true
	}
	var fresh []string
	for _, v := range after {
		if !seen[v.Version] {
			fresh = append(fresh, v.Version)
		}
	}
	switch len(fresh) {
	case 0:
		return "", apperr.Wrap(apperr.Upstream, cause, "create a version of %s: it did not land; safe to re-run", ap.Name)
	case 1:
		return fresh[0], nil
	default:
		return "", apperr.New(apperr.Conflict, "create a version of %s: %d new versions appeared (%v); someone else is writing", ap.Name, len(fresh), fresh)
	}
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
