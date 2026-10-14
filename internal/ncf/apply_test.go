package ncf_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncftest"
)

// fakeClock advances only when apply sleeps.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.t = c.t.Add(d)
	return nil
}

func apply(t *testing.T, s *ncftest.Store, f *ncf.File, mutate func(*ncf.ApplyOptions)) (*ncf.ApplyResult, error) {
	t.Helper()
	p := plan(t, s, f, defaults)
	clock := &fakeClock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	opts := ncf.ApplyOptions{PlanOptions: defaults, ExpectDigest: p.Digest, Now: clock.now, Sleep: clock.sleep}
	if mutate != nil {
		mutate(&opts)
	}
	_, res, err := checker().Apply(context.Background(), s, s, f, nil, opts)
	return res, err
}

var ambiguous = &apperr.Error{Code: apperr.Upstream, Message: "POST: EOF", Upstream: &apperr.UpstreamDetail{Method: "POST", Ambiguous: true}}

func TestApplyCreatesVerifiesActivatesAndWaits(t *testing.T) {
	s := world()
	s.ProdLag = 3
	res, err := apply(t, s, desired("192.0.2.0/25", "198.51.100.9"), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := res.Aliases[0]
	if a.Status != ncf.StatusDeployed || a.FromVersion != "V1" || a.Version != "V2" {
		t.Errorf("result = %+v", a)
	}
	live := s.Live(101)
	if live.ActiveVersion != "V2" || live.ProdVersion != "V2" || !ncf.SameEntries(live.Entries, []string{"192.0.2.0/25", "198.51.100.9/32"}) {
		t.Errorf("live = %+v", live)
	}
	if s.Count("CreateVersion") != 1 || s.Count("Activate") != 1 {
		t.Errorf("calls = %v", s.Calls)
	}
}

func TestApplyNothingToDo(t *testing.T) {
	s := world()
	res, err := apply(t, s, desired("192.0.2.0/25", "198.51.100.7"), nil)
	if err != nil || res.Aliases[0].Status != ncf.StatusUnchanged || s.Count("CreateVersion") != 0 {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

func TestApplyRefusesAMovedDigest(t *testing.T) {
	s := world()
	_, err := apply(t, s, desired("192.0.2.0/25"), func(o *ncf.ApplyOptions) { o.ExpectDigest = "sha256:reviewed-something-else" })
	if apperr.CodeOf(err) != apperr.Drift || s.Count("CreateVersion") != 0 {
		t.Errorf("err = %v, calls %v", err, s.Calls)
	}
}

func TestApplyRefusesPlanErrors(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "203.0.113.0/24") // own space via protected-dst
	_, _, err := checker().Apply(context.Background(), s, s, f, nil, ncf.ApplyOptions{PlanOptions: defaults})
	if apperr.CodeOf(err) != apperr.Validation || s.Count("CreateVersion") != 0 {
		t.Errorf("err = %v", err)
	}
}

func TestApplyConflictWhenTheTokenMovesAfterPlanning(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25")
	p := plan(t, s, f, defaults)
	// Someone activates a version between apply's own re-plan and its
	// pre-write re-read: the digest still matches, the token doesn't.
	calls := 0
	read := &hookStore{Store: s, onGetAlias: func() {
		if calls++; calls == 3 { // 1 own-space alias, 2 block-v4 in the re-plan, 3 the pre-write re-read
			s.ActivateNow(101, "192.0.2.0/25", "198.51.100.7")
		}
	}}
	_, res, err := checker().Apply(context.Background(), read, s, f, nil, ncf.ApplyOptions{PlanOptions: defaults, ExpectDigest: p.Digest})
	if apperr.CodeOf(err) != apperr.Conflict || s.Count("CreateVersion") != 0 || res.Aliases[0].Status != ncf.StatusFailed {
		t.Errorf("err = %v, res = %+v", err, res)
	}
}

type hookStore struct {
	*ncftest.Store
	onGetAlias func()
}

func (h *hookStore) GetAlias(ctx context.Context, id int64) (ncf.LiveAlias, error) {
	if id == 101 || id == 102 {
		h.onGetAlias()
	}
	return h.Store.GetAlias(ctx, id)
}

func TestApplyAmbiguousCreateThatLanded(t *testing.T) {
	s := world()
	s.CreateErr, s.CreateLands = ambiguous, true
	res, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if err != nil || res.Aliases[0].Version != "V2" || res.Aliases[0].Status != ncf.StatusDeployed {
		t.Errorf("res = %+v, err = %v", res, err)
	}
	if s.Count("CreateVersion") != 1 {
		t.Errorf("CreateVersion sent %d times; it must never be retried", s.Count("CreateVersion"))
	}
}

func TestApplyAmbiguousCreateThatDidNotLand(t *testing.T) {
	s := world()
	s.CreateErr = ambiguous
	_, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if apperr.CodeOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "did not land; safe to re-run") || s.Count("CreateVersion") != 1 {
		t.Errorf("err = %v, calls %v", err, s.Calls)
	}
}

func TestApplyAmbiguousCreateWithAConcurrentWriter(t *testing.T) {
	s := world()
	s.CreateErr, s.CreateLands = ambiguous, true
	s.BeforeCreate = func(s *ncftest.Store) { s.AddVersions(101, 1) }
	_, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if apperr.CodeOf(err) != apperr.Conflict {
		t.Errorf("err = %v", err)
	}
}

func TestApplyNonAmbiguousCreateFailureIsNotProbed(t *testing.T) {
	s := world()
	s.CreateErr = apperr.New(apperr.Upstream, "HTTP 400: bad entry")
	_, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if err == nil || s.Count("ListVersions") != 1 { // only the pre-create snapshot
		t.Errorf("err = %v, calls %v", err, s.Calls)
	}
}

func TestApplyLeavesAMismatchedVersionInactive(t *testing.T) {
	s := world()
	s.Corrupt = func(es []string) []string { return append(es, "198.51.100.200") }
	res, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if apperr.CodeOf(err) != apperr.Upstream || s.Count("Activate") != 0 || res.Aliases[0].Status != ncf.StatusFailed {
		t.Errorf("err = %v, res = %+v", err, res)
	}
	if s.Live(101).ActiveVersion != "V1" {
		t.Error("the mismatched version was activated")
	}
}

func TestApplyActivatesNothingUntilEveryVersionVerifies(t *testing.T) {
	s := world()
	s.Add(ncf.LiveAlias{ID: 103, Name: "block-v4-b", Type: "SOURCE", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, "192.0.2.128/25")
	f := desired("192.0.2.0/25")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "block-v4-b", ID: 103, Type: "SOURCE", Role: ncf.RoleDeny, Entries: entries("192.0.2.128/26")})
	n := 0
	s.Corrupt = func(es []string) []string {
		if n++; n == 2 {
			return nil // the second alias's version comes back wrong
		}
		return es
	}
	res, err := apply(t, s, f, nil)
	if err == nil || s.Count("Activate") != 0 {
		t.Errorf("err = %v, calls %v", err, s.Calls)
	}
	got := []ncf.Status{res.Aliases[0].Status, res.Aliases[1].Status}
	if !slices.Equal(got, []ncf.Status{ncf.StatusCreated, ncf.StatusFailed}) {
		t.Errorf("statuses = %v", got)
	}
}

func TestApplyAmbiguousActivateThatTookEffect(t *testing.T) {
	s := world()
	s.ActivateErr, s.ActivateLands = ambiguous, true
	res, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if err != nil || res.Aliases[0].Status != ncf.StatusDeployed || s.Count("Activate") != 1 {
		t.Errorf("err = %v, res = %+v", err, res)
	}
}

func TestApplyTimesOutWaitingForProduction(t *testing.T) {
	s := world()
	s.ProdLag = 1000
	res, err := apply(t, s, desired("192.0.2.0/25"), func(o *ncf.ApplyOptions) { o.Timeout = time.Minute })
	if apperr.CodeOf(err) != apperr.Upstream || res.Aliases[0].Status != ncf.StatusActive {
		t.Errorf("err = %v, res = %+v", err, res)
	}
}

func TestApplyReportsFailedRules(t *testing.T) {
	s := world()
	s.Deploy = ncf.Deployment{FailedRules: 2}
	res, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if apperr.CodeOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "2 failed rules") || res.Aliases[0].Status != ncf.StatusActive {
		t.Errorf("err = %v, res = %+v", err, res)
	}
}

func TestApplyOnAnUnversionedAPIIsUnsupported(t *testing.T) {
	s := world()
	s.Unversioned = true
	_, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if apperr.CodeOf(err) != apperr.NotFound || s.Count("CreateVersion") != 0 {
		t.Errorf("err = %v, calls %v", err, s.Calls)
	}
}
