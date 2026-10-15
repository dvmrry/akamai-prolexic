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

func TestApplyReportsAFailedRuleset(t *testing.T) {
	for _, tt := range []struct {
		name    string
		deploy  ncf.Deployment
		wantErr bool
	}{
		{"newer FAILED ruleset, no failed rules", ncf.Deployment{Version: 7, State: "PRODUCTION", FailedVersion: 8}, true},
		{"nothing in production", ncf.Deployment{State: "FAILED", FailedVersion: 3}, true},
		{"older FAILED ruleset is history", ncf.Deployment{Version: 7, State: "PRODUCTION", FailedVersion: 5}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := world()
			s.Deploy = tt.deploy
			res, err := apply(t, s, desired("192.0.2.0/25"), nil)
			if (err != nil) != tt.wantErr || (tt.wantErr && res.Aliases[0].Status != ncf.StatusActive) {
				t.Errorf("err = %v, res = %+v", err, res)
			}
		})
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

// bigWorld adds a BIG alias (51+ entries) next to world's SOURCE alias.
func bigWorld() (*ncftest.Store, *ncf.File, []string) {
	s := world()
	var live []string
	for i := range 60 {
		live = append(live, fmt.Sprintf("198.51.100.%d", i))
	}
	s.Add(ncf.LiveAlias{ID: 104, Name: "block-big", Type: "BIG", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, live...)
	f := desired("192.0.2.0/25")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "block-big", ID: 104, Type: "BIG", Role: ncf.RoleDeny, Entries: entries(append(live[1:], "198.51.100.200")...)})
	return s, f, live
}

func TestApplyCommentsCarryTheDigest(t *testing.T) {
	s := world()
	res, err := apply(t, s, desired("192.0.2.0/25"), nil)
	if err != nil || len(s.Comments) != 1 || s.Comments[0] != "prolexic apply "+res.Digest {
		t.Errorf("err = %v, comments = %q", err, s.Comments)
	}
}

func TestApplyBigUploadThatActivatesOnArrival(t *testing.T) {
	s, f, _ := bigWorld()
	s.BigActivates = true
	res, err := apply(t, s, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Count("Activate") != 1 { // only the SOURCE alias; the BIG one was active already
		t.Errorf("calls = %v", s.Calls)
	}
	if got := s.Calls[slices.Index(s.Calls, "CreateVersion")+1:]; slices.Index(got, "CreateVersion") < 0 {
		t.Errorf("expected two creates, calls = %v", s.Calls)
	}
	for _, a := range res.Aliases {
		if a.Status != ncf.StatusDeployed {
			t.Errorf("%s: %s", a.Name, a.Status)
		}
	}
}

func TestApplyCreatesBigVersionsLast(t *testing.T) {
	s, f, _ := bigWorld()
	s.BigActivates = true
	// The SOURCE alias fails verification: the BIG upload, which would go
	// live on arrival, must never be sent.
	s.Corrupt = func(es []string) []string { return append(es, "203.0.113.200") }
	_, err := apply(t, s, f, nil)
	if err == nil || s.Count("CreateVersion") != 1 || s.Live(104).ActiveVersion != "V1" {
		t.Errorf("err = %v, calls = %v", err, s.Calls)
	}
}

func TestApplyRollsBackABadBigUpload(t *testing.T) {
	s, f, _ := bigWorld()
	s.BigActivates = true
	n := 0
	s.Corrupt = func(es []string) []string {
		if n++; n == 2 { // the BIG upload, created second
			return es[1:]
		}
		return es
	}
	res, err := apply(t, s, f, nil)
	big := res.Aliases[0] // sorted by name: block-big first
	if apperr.CodeOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "V1 was re-activated") ||
		s.Live(104).ActiveVersion != "V1" || big.Status != ncf.StatusRolledBack || big.Error == "" || s.Count("Activate") != 1 {
		t.Errorf("err = %v, big = %+v, calls = %v", err, big, s.Calls)
	}
	if s.Live(101).ActiveVersion != "V1" {
		t.Error("the SOURCE alias was activated although the apply failed")
	}
}

func TestApplyDoesNotWaitForAnAliasNoRuleUses(t *testing.T) {
	s := world()
	s.Unused(101)
	res, err := apply(t, s, desired("192.0.2.0/25"), func(o *ncf.ApplyOptions) { o.Timeout = time.Minute })
	if err != nil || res.Aliases[0].Status != ncf.StatusActive || s.Live(101).ActiveVersion != "V2" {
		t.Errorf("err = %v, res = %+v", err, res)
	}
	if s.Count("Deployment") != 0 {
		t.Errorf("waited on the deployment for an alias no rule uses: %v", s.Calls)
	}
}

func TestApplyRollsBackEveryUploadThatWentLive(t *testing.T) {
	s, f, live := bigWorld()
	s.Add(ncf.LiveAlias{ID: 105, Name: "block-big-2", Type: "BIG", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, live...)
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "block-big-2", ID: 105, Type: "BIG", Role: ncf.RoleDeny, Entries: entries(append(live[2:], "198.51.100.201")...)})
	s.BigActivates = true
	n := 0
	s.Corrupt = func(es []string) []string {
		if n++; n == 3 { // SOURCE, block-big, then block-big-2 comes back wrong
			return es[1:]
		}
		return es
	}
	res, err := apply(t, s, f, nil)
	if err == nil {
		t.Fatal("apply succeeded")
	}
	for _, id := range []int64{101, 104, 105} {
		if v := s.Live(id).ActiveVersion; v != "V1" {
			t.Errorf("alias %d is on %s; nothing may stay live after a failed apply", id, v)
		}
	}
	got := map[string]ncf.Status{}
	for _, a := range res.Aliases {
		got[a.Name] = a.Status
	}
	if got["block-big"] != ncf.StatusRolledBack || got["block-big-2"] != ncf.StatusRolledBack || got["block-v4"] != ncf.StatusCreated {
		t.Errorf("statuses = %v", got)
	}
}

func TestApplyRollsBackAnUploadItCannotReRead(t *testing.T) {
	s, f, _ := bigWorld()
	f.Aliases = f.Aliases[1:] // just the BIG alias
	s.BigActivates = true
	s.GetVersionErr = &apperr.Error{Code: apperr.Upstream, Message: "HTTP 503"}
	res, err := apply(t, s, f, nil)
	if err == nil || !strings.Contains(err.Error(), "couldn't be re-read") || s.Live(104).ActiveVersion != "V1" {
		t.Errorf("err = %v, res = %+v, live = %+v", err, res, s.Live(104))
	}
}

func TestApplyRollsBackActivationsWhenALaterOneFails(t *testing.T) {
	s := world()
	s.Add(ncf.LiveAlias{ID: 103, Name: "block-v4-b", Type: "SOURCE", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, "192.0.2.128/25")
	f := desired("192.0.2.0/25")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "block-v4-b", ID: 103, Type: "SOURCE", Role: ncf.RoleDeny, Entries: entries("192.0.2.128/26")})
	s.ActivateFails = map[int64]error{103: apperr.New(apperr.Upstream, "HTTP 400: bad")}
	res, err := apply(t, s, f, nil)
	if err == nil || s.Live(101).ActiveVersion != "V1" || s.Live(103).ActiveVersion != "V1" {
		t.Errorf("err = %v, live 101 = %s, 103 = %s", err, s.Live(101).ActiveVersion, s.Live(103).ActiveVersion)
	}
	if res.Aliases[0].Status != ncf.StatusRolledBack || res.Aliases[1].Status != ncf.StatusFailed {
		t.Errorf("statuses = %s, %s", res.Aliases[0].Status, res.Aliases[1].Status)
	}
}

func TestApplyWaitsOnTheListNotOnEntries(t *testing.T) {
	s := world()
	s.ProdLag = 5
	if _, err := apply(t, s, desired("192.0.2.0/25"), nil); err != nil {
		t.Fatal(err)
	}
	// Two plans (the helper's and apply's own, 2 aliases each) plus the
	// pre-create re-read: 5. Polling on GetAlias would add one per poll.
	if n := s.Count("GetAlias"); n != 5 {
		t.Errorf("GetAlias called %d times; polling must use the alias list", n)
	}
}
