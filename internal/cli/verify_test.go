package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// savePlan runs plan and saves its JSON, as a pipeline does.
func savePlan(t *testing.T, api *fakeAPI, desired string) string {
	t.Helper()
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", desired)
	if r.code != 0 {
		t.Fatalf("plan: exit %d: %s", r.code, r.stderr)
	}
	p := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(p, []byte(r.stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyMatchingPlan(t *testing.T) {
	api := ncfAPI(t)
	plan := savePlan(t, api, writeDesired(t, desiredFixture)) // live already matches
	before := len(api.calls)
	r := runCLI(t, ncfEnv(api.env()), "verify", "--plan", plan)
	doc := decode[VerifyDoc](t, r.stdout, "prolexic.verify.v1")
	if r.code != 0 || !doc.Verified || len(doc.Aliases) != 1 || !doc.Aliases[0].Verified {
		t.Errorf("exit = %d, doc = %+v, stderr = %s", r.code, doc, r.stderr)
	}
	for _, c := range api.calls[before:] {
		if c.Method != "GET" {
			t.Errorf("verify sent a non-GET: %s %s", c.Method, c.Path)
		}
	}
}

func TestVerifyUnappliedPlanIsDrift(t *testing.T) {
	api := ncfAPI(t)
	desired := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", desired, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r")
	plan := savePlan(t, api, desired) // never applied
	r := runCLI(t, ncfEnv(api.env()), "verify", "--plan", plan)
	doc := decode[VerifyDoc](t, r.stdout, "prolexic.verify.v1")
	if r.code != exitCode(apperr.Drift) || doc.Verified || len(doc.Aliases[0].Missing) != 1 || !strings.Contains(r.stderr, "don't match the plan") {
		t.Errorf("exit = %d, doc = %+v, stderr = %s", r.code, doc, r.stderr)
	}
}

func TestVerifyNeedsAPlanDocument(t *testing.T) {
	notPlan := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(notPlan, []byte(`{"schema":"prolexic.status.v1"}`), 0o600)
	for _, args := range [][]string{{"verify"}, {"verify", "--plan", notPlan}} {
		if r := runCLI(t, Env{}, args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d: %s", args, r.code, r.stderr)
		}
	}
	if r := runCLI(t, Env{}, "verify", "--plan", filepath.Join(t.TempDir(), "missing.json")); r.code != exitCode(apperr.NotFound) {
		t.Errorf("missing file: exit = %d", r.code)
	}
}
