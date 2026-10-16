package ncf_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncftest"
)

// Pessimistic fakes: Akamai behaving differently from what prolexic assumes.
// Each must end in a clear, safe failure, never a wrong success or a false
// message.

// silentActivate accepts every activation and does nothing.
type silentActivate struct{ *ncftest.Store }

func (silentActivate) Activate(context.Context, int64, string) error { return nil }

// raceActivate activates, then another writer activates something else.
type raceActivate struct{ *ncftest.Store }

func (r raceActivate) Activate(ctx context.Context, id int64, v string) error {
	if err := r.Store.Activate(ctx, id, v); err != nil {
		return err
	}
	r.ActivateNow(id, "203.0.113.250")
	return nil
}

func applyThrough(t *testing.T, s *ncftest.Store, write ncf.Store, f *ncf.File) (*ncf.ApplyResult, error) {
	t.Helper()
	p := plan(t, s, f, defaults)
	clock := &fakeClock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	_, res, err := checker().Apply(context.Background(), s, write, f, nil, ncf.ApplyOptions{PlanOptions: defaults, Reviewed: p, Now: clock.now, Sleep: clock.sleep})
	return res, err
}

func TestApplyAnActivationThatDoesNothingIsSaidPlainly(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9")
	res, err := applyThrough(t, s, silentActivate{s}, f)
	if apperr.KindOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "didn't take effect") || strings.Contains(err.Error(), "are active") {
		t.Errorf("err = %v", err)
	}
	if a := res.Aliases[0]; a.Status != ncf.StatusFailed {
		t.Errorf("status = %s, want failed: confirmed at activation, not at the production timeout", a.Status)
	}
	// Once activation works, a re-run finishes with the same version.
	if _, err := applyThrough(t, s, s, f); err != nil || s.Live(101).ActiveVersion != "V2" {
		t.Errorf("re-run: %v, live %+v", err, s.Live(101))
	}
}

func TestApplySomeoneElseActivatingIsAConflict(t *testing.T) {
	s := world()
	_, err := applyThrough(t, s, raceActivate{s}, desired("192.0.2.0/25", "198.51.100.9"))
	if apperr.KindOf(err) != apperr.Conflict || !strings.Contains(err.Error(), "someone else activated it") {
		t.Errorf("err = %v", err)
	}
}

// An own-space alias that reads back empty (or a blanked read) protects
// nothing: the plan must say so, not pass every deny entry.
func TestPlanRefusesAnEmptyOwnSpaceAlias(t *testing.T) {
	s := world()
	s.ActivateNow(102) // protected-dst, now empty
	f := desired("192.0.2.0/25", "198.51.100.7")
	if got := findingCodes(plan(t, s, f, defaults).Findings); !slices.Contains(got, "error own_space_alias protected-dst") {
		t.Errorf("findings = %q", got)
	}
}

// A deployment status with no production ACL version, while aliases are in
// production, is no evidence of a healthy deployment.
func TestAnEmptyDeploymentStatusIsNotHealthy(t *testing.T) {
	s := world()
	s.UseInRule(101, 1)
	s.Deploy = ncf.Deployment{} // what an empty answer decodes to
	f := desired("192.0.2.0/25", "198.51.100.9")
	p := roundTrip(t, plan(t, s, f, defaults))
	_, err := applyThrough(t, s, s, f)
	if apperr.KindOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "no production ACL version") {
		t.Errorf("apply: err = %v", err)
	}
	v, _ := ncf.Verify(context.Background(), s, p)
	if v.Verified || len(v.Deployment) == 0 {
		t.Errorf("verify: %+v", v)
	}
}

// An alias no deployed rule uses never reaches production, so nothing after
// the activation would notice it didn't happen: the activation itself must be
// confirmed.
func TestApplyConfirmsActivationWithoutProduction(t *testing.T) {
	s := world()
	s.Lag(101, "") // no deployed rule uses it: no production version
	_, err := applyThrough(t, s, silentActivate{s}, desired("192.0.2.0/25", "198.51.100.9"))
	if err == nil || !strings.Contains(err.Error(), "didn't take effect") {
		t.Errorf("err = %v; an activation that didn't happen must not exit 0", err)
	}
}

// dupList answers the alias list with one alias listed twice.
type dupList struct{ *ncftest.Store }

func (d dupList) ListAliases(ctx context.Context) ([]ncf.LiveAlias, error) {
	all, err := d.Store.ListAliases(ctx)
	if err != nil || len(all) == 0 {
		return all, err
	}
	other := all[0]
	other.Name = "other-v4"
	return append(all, other), nil
}

func TestPlanRefusesAnAliasListedTwice(t *testing.T) {
	s := world()
	_, err := checker().MakePlan(context.Background(), dupList{s}, desired("192.0.2.0/25"), nil, defaults)
	if apperr.KindOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "twice") {
		t.Errorf("err = %v", err)
	}
}

func TestVerifySaysAPlanLooksUnapplied(t *testing.T) {
	s := world()
	p := roundTrip(t, plan(t, s, desired("192.0.2.0/25", "198.51.100.9"), defaults))
	v, _ := ncf.Verify(context.Background(), s, p)
	probs := strings.Join(v.Aliases[0].Problems, "; ")
	if !strings.Contains(probs, "looks unapplied") || !strings.Contains(probs, "1 added entry isn't live") {
		t.Errorf("problems = %s", probs)
	}
}

// recordingSilent accepts every activation, does nothing, and records them.
type recordingSilent struct {
	*ncftest.Store
	activations *[]string
}

func (r recordingSilent) Activate(_ context.Context, id int64, v string) error {
	*r.activations = append(*r.activations, fmt.Sprintf("%d/%s", id, v))
	return nil
}

// An activation accepted but never confirmed may land later: rollback
// re-activates the replaced version to supersede it, and the result marks it.
func TestRollbackSupersedesAnUnconfirmedActivation(t *testing.T) {
	s := world()
	var got []string
	res, err := applyThrough(t, s, recordingSilent{s, &got}, desired("192.0.2.0/25", "198.51.100.9"))
	if err == nil {
		t.Fatal("an activation that didn't take effect succeeded")
	}
	if !slices.Equal(got, []string{"101/V2", "101/V1"}) {
		t.Errorf("activations = %v, want ours then the replaced version again", got)
	}
	if a := res.Aliases[0]; !a.Unconfirmed || a.Status != ncf.StatusFailed { // the failing alias is reported failed, and marked unconfirmed
		t.Errorf("result = %+v", a)
	}
}

// The digest covers the checks a plan ran with: a reviewed plan can't be
// applied with weaker ones.
func TestApplyRefusesWeakerChecksThanReviewed(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9")
	reviewed := plan(t, s, f, defaults) // with live own space
	weaker := ncf.PlanOptions{MaxRemovals: defaults.MaxRemovals, SkipLiveOwnSpace: true}
	if skipped := plan(t, s, f, weaker); skipped.Digest == reviewed.Digest {
		t.Fatal("skipping live own space left the digest unchanged")
	}
	_, _, err := checker().Apply(context.Background(), s, s, f, nil, ncf.ApplyOptions{PlanOptions: weaker, Reviewed: reviewed})
	if apperr.KindOf(err) != apperr.Validation || s.Count("CreateVersion") != 0 {
		t.Errorf("err = %v, creates = %d", err, s.Count("CreateVersion"))
	}
}

// dupName answers the alias list with a second alias named protected-dst.
type dupName struct{ *ncftest.Store }

func (d dupName) ListAliases(ctx context.Context) ([]ncf.LiveAlias, error) {
	all, err := d.Store.ListAliases(ctx)
	if err != nil {
		return all, err
	}
	for _, l := range all {
		if l.Name == "protected-dst" {
			l.ID = 999
			return append(all, l), nil
		}
	}
	return all, nil
}

// Own space is named, so an own-space name that more than one live alias
// carries is an error, not a guess at which one protects what.
func TestPlanRefusesAnAmbiguousOwnSpaceName(t *testing.T) {
	p, err := checker().MakePlan(context.Background(), dupName{world()}, desired("192.0.2.0/25", "198.51.100.7"), nil, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if got := findingCodes(p.Findings); !slices.Contains(got, "error own_space_alias protected-dst") {
		t.Errorf("findings = %q", got)
	}
}
