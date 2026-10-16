package ncf_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
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
