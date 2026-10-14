package cli

import (
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Live answers 404 NOT_FOUND for a window with no attacks.
func TestAttacksListEmptyWindowIs404(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/attack-reports/contract/example-a/start/1767225600/end/1767312000", 404,
		`{"errorCode":"NOT_FOUND","message":"no attacks"}`)
	api.json("GET /prolexic-analytics/v2/attack-reports/contract/example-b/start/1767225600/end/1767312000", 200, attacksFixture)
	api.json("GET /prolexic-analytics/v2/attack-reports/contract/example-c/start/1767225600/end/1767312000", 403,
		`{"errorCode":"FORBIDDEN","message":"no access"}`)
	env := api.env()
	env.Now = func() time.Time { return fixedNow }

	r := runCLI(t, env, "attacks", "list", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if len(doc.Attacks) != 0 || len(doc.Failures) != 0 {
		t.Errorf("doc = %+v", doc)
	}

	// The empty name does not hide the others, and other errors still fail.
	r = runCLI(t, env, "attacks", "list", "--customer", "example-a,example-b")
	doc = decode[AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if r.code != 0 || len(doc.Attacks) != 2 {
		t.Errorf("exit %d, attacks %d", r.code, len(doc.Attacks))
	}
	r = runCLI(t, env, "attacks", "list", "--customer", "example-a,example-c")
	if r.code != int(apperr.Credentials) {
		t.Errorf("exit = %d, want 3", r.code)
	}
}

func TestAttacksShowMissingIs404(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/attack-report/contract/example-a/attack-id/9", 404, `{"errorCode":"NOT_FOUND","message":"no such attack"}`)
	if r := runCLI(t, api.env(), "attacks", "show", "--id", "9", "--customer", "example-a"); r.code != int(apperr.NotFound) {
		t.Errorf("exit = %d, want 4", r.code)
	}
}
