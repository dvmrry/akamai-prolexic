package ncf_test

import (
	"context"
	"encoding/json"
	"maps"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncftest"
)

// roundTrip is the plan as a pipeline hands it on: a JSON artifact.
func roundTrip(t *testing.T, p *ncf.Plan) *ncf.Plan {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out ncf.Plan
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestVerifyComparesThePlanWithAFreshRead(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9") // adds .9, removes .7
	p := roundTrip(t, plan(t, s, f, defaults))

	before, err := ncf.Verify(context.Background(), s, p)
	if err != nil || before.Verified || before.Aliases[0].Missing[0] != "198.51.100.9/32" || before.Aliases[0].StillLive[0] != "198.51.100.7/32" {
		t.Fatalf("before apply: %+v, err = %v", before, err)
	}
	if _, err := apply(t, s, f, nil); err != nil {
		t.Fatal(err)
	}
	after, err := ncf.Verify(context.Background(), s, p)
	if err != nil || !after.Verified || after.Digest != p.Digest {
		t.Fatalf("after apply: %+v, err = %v", after, err)
	}

	s.ActivateNow(101, "192.0.2.0/25", "198.51.100.9", "203.0.113.200") // someone adds an entry
	extra, _ := ncf.Verify(context.Background(), s, p)
	if extra.Verified || extra.Aliases[0].Live != 3 || extra.Aliases[0].Want != 2 {
		t.Errorf("an extra entry: %+v", extra.Aliases[0])
	}
}

func TestVerifyNeedsProductionToCarryTheActiveVersion(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9")
	p := plan(t, s, f, defaults)
	if _, err := apply(t, s, f, nil); err != nil {
		t.Fatal(err)
	}
	s.Lag(101, "V1") // production falls back behind the active version
	v, _ := ncf.Verify(context.Background(), s, p)
	if v.Verified || !v.Aliases[0].ProductionLag {
		t.Errorf("lagging production verified: %+v", v.Aliases[0])
	}
}

func TestVerifyRefusesAPlanWithErrors(t *testing.T) {
	p := &ncf.Plan{Findings: []ncf.Finding{{Severity: ncf.Error, Code: "own_space"}}}
	if _, err := ncf.Verify(context.Background(), world(), p); apperr.KindOf(err) != apperr.Validation {
		t.Errorf("err = %v", err)
	}
}

// applied returns a store with desired applied and the plan for it, as CI
// would have saved it.
func applied(t *testing.T) (*ncftest.Store, *ncf.File, *ncf.Plan) {
	t.Helper()
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9")
	p := roundTrip(t, plan(t, s, f, defaults))
	if _, err := apply(t, s, f, nil); err != nil {
		t.Fatal(err)
	}
	return s, f, p
}

func TestVerifyCatchesAReplacedUnchangedEntry(t *testing.T) {
	s, _, p := applied(t)
	s.ActivateNow(101, "203.0.113.200", "198.51.100.9") // the unchanged /25 swapped: same count
	v, _ := ncf.Verify(context.Background(), s, p)
	if v.Verified || v.Aliases[0].SameSet {
		t.Errorf("a swapped entry verified: %+v", v.Aliases[0])
	}
}

func TestVerifyRefusesAnEditedPlan(t *testing.T) {
	s, _, p := applied(t)
	truncated := *p
	truncated.Aliases = nil
	edited := roundTrip(t, p)
	edited.Aliases[0].Add = nil
	stripped := roundTrip(t, p)
	stripped.Aliases[0].DesiredHash = ""
	for name, q := range map[string]*ncf.Plan{"truncated": &truncated, "edited": edited, "stripped": stripped} {
		if _, err := ncf.Verify(context.Background(), s, q); apperr.KindOf(err) != apperr.Validation {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
	}
}

func TestVerifyNeedsAHealthySettledDeployment(t *testing.T) {
	for name, d := range map[string]ncf.Deployment{
		"failed rules": {Version: 7, FailedRules: 2},
		"processing":   {Version: 7, Processing: true},
	} {
		s, _, p := applied(t)
		s.Deploy = d
		v, err := ncf.Verify(context.Background(), s, p)
		if err != nil || v.Verified || len(v.Deployment) != 1 {
			t.Errorf("%s: %+v, err = %v", name, v, err)
		}
	}
}

func TestVerifyNoticesAnAliasLeavingProduction(t *testing.T) {
	s := world()
	s.UseInRule(101, 1) // in production before the change
	f := desired("192.0.2.0/25", "198.51.100.9")
	p := roundTrip(t, plan(t, s, f, defaults))
	if p.Aliases[0].ProdVersion == "" {
		t.Fatal("fixture: the plan should see production")
	}
	if _, err := apply(t, s, f, nil); err != nil {
		t.Fatal(err)
	}
	s.Lag(101, "") // no deployed rule uses it any more
	v, _ := ncf.Verify(context.Background(), s, p)
	if v.Verified || !v.Aliases[0].ProductionLag {
		t.Errorf("left production but verified: %+v", v.Aliases[0])
	}
}

// Verify lists aliases once, then reads entries by version: never a full
// alias read (list plus entries) per alias.
func TestVerifyListsOnce(t *testing.T) {
	s, _, p := applied(t)
	lists, gets := s.Count("ListAliases"), s.Count("GetAlias")
	if _, err := ncf.Verify(context.Background(), s, p); err != nil {
		t.Fatal(err)
	}
	if n := s.Count("ListAliases") - lists; n != 1 {
		t.Errorf("ListAliases called %d times", n)
	}
	if n := s.Count("GetAlias") - gets; n != 0 {
		t.Errorf("GetAlias called %d times", n)
	}
}

// FuzzPlanDiff: for any live set and desired set (drawn from a pool, live in
// the API's spellings), live minus the plan's removes plus its adds is
// exactly the desired set, and unchanged counts the rest.
func FuzzPlanDiff(f *testing.F) {
	pool := []struct{ authored, live string }{
		{"192.0.2.0/25", "192.0.2.0/25"}, {"198.51.100.7", "198.51.100.7/32"}, {"198.51.100.8/32", "198.51.100.8"},
		{"198.51.100.64/26", "198.51.100.64/26"}, {"GEO::DE", "GEO::DE"}, {"ASN::64500", "ASN::64500"},
		{"192.0.2.128/25", "192.0.2.128/25"}, {"198.51.100.9", "198.51.100.9/32"},
	}
	f.Add(uint8(0b00000011), uint8(0b00000110))
	f.Add(uint8(0), uint8(0xff))
	f.Add(uint8(0xff), uint8(0))
	f.Fuzz(func(t *testing.T, liveBits, wantBits uint8) {
		var live, want []string
		for i, e := range pool {
			if liveBits&(1<<i) != 0 {
				live = append(live, e.live)
			}
			if wantBits&(1<<i) != 0 {
				want = append(want, e.authored)
			}
		}
		s := world()
		s.ActivateNow(101, live...)
		p := plan(t, s, desired(want...), ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive})
		if len(p.Aliases) != 1 {
			t.Fatalf("plan = %+v", p)
		}
		ap := p.Aliases[0]
		result := map[string]bool{}
		for _, e := range live {
			result[canon(t, e)] = true
		}
		for _, e := range ap.Remove {
			delete(result, canon(t, e.CIDR))
		}
		for _, e := range ap.Add {
			result[canon(t, e.CIDR)] = true
		}
		wantSet := map[string]bool{}
		for _, e := range want {
			wantSet[canon(t, e)] = true
		}
		if !maps.Equal(result, wantSet) {
			t.Fatalf("live %v, want %v: live - remove %v + add %v = %v", live, want, ap.Remove, ap.Add, result)
		}
		if ap.Unchanged != len(wantSet)-len(ap.Add) {
			t.Fatalf("unchanged = %d, want %d", ap.Unchanged, len(wantSet)-len(ap.Add))
		}
	})
}

func canon(t *testing.T, s string) string {
	t.Helper()
	v, err := ncf.ParseLive(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return v.String()
}
