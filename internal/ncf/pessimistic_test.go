package ncf_test

import (
	"context"
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
	_, res, err := checker().Apply(context.Background(), s, write, f, nil, ncf.ApplyOptions{PlanOptions: defaults, ExpectDigest: p.Digest, Now: clock.now, Sleep: clock.sleep})
	return res, err
}

func TestApplyAnActivationThatDoesNothingIsSaidPlainly(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9")
	res, err := applyThrough(t, s, silentActivate{s}, f)
	if apperr.KindOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "didn't take effect") || strings.Contains(err.Error(), "are active") {
		t.Errorf("err = %v", err)
	}
	if a := res.Aliases[0]; a.Status != ncf.StatusCreated {
		t.Errorf("status = %s, want created: the version exists but isn't active", a.Status)
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
