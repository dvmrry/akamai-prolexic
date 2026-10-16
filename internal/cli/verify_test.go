package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// The CI flow with one artifact: plan --out saves it, apply --plan takes its
// digest, verify --plan reads it back.
func TestPlanApplyVerifyWithOneArtifact(t *testing.T) {
	api, _ := ncfAPIState(t)
	desired := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", desired, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r")
	saved := filepath.Join(t.TempDir(), "plan.json")

	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", desired, "--out", saved)
	if r.code != 0 || !strings.Contains(r.stdout, "digest: sha256:") || strings.HasPrefix(strings.TrimSpace(r.stdout), "{") {
		t.Fatalf("plan --out: exit %d, stdout should be the text plan:\n%s%s", r.code, r.stdout, r.stderr)
	}
	b, _ := os.ReadFile(saved)
	planDoc := decode[PlanDoc](t, string(b), "prolexic.plan.v1")
	if !strings.Contains(r.stdout, planDoc.Digest) {
		t.Errorf("the text and the saved JSON disagree on the digest %s", planDoc.Digest)
	}

	env := ncfEnv(api.env())
	read := env.Getenv
	env.Getenv = func(k string) string { return read(strings.Replace(k, "AKAMAI_WRITE_", "AKAMAI_", 1)) }
	if r = runCLI(t, env, "apply", "--file", desired, "--plan", saved, "--interval", "1ms", "--timeout", "5s"); r.code != 0 {
		t.Fatalf("apply --plan: exit %d: %s", r.code, r.stderr)
	}
	if r = runCLI(t, ncfEnv(api.env()), "verify", "--plan", saved); r.code != 0 {
		t.Errorf("verify after apply: exit %d: %s%s", r.code, r.stdout, r.stderr)
	}
}

func TestApplyTakesExactlyOneReviewedDigest(t *testing.T) {
	desired := writeDesired(t, desiredFixture)
	for _, args := range [][]string{
		{"apply", "--file", desired},
		{"apply", "--file", desired, "--plan", "p.json", "--expect-digest", "sha256:x"},
	} {
		if r := runCLI(t, Env{}, args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit %d: %s", args[3:], r.code, r.stderr)
		}
	}
}

// Every document says when and by which prolexic it was made; apply and
// verify also carry the account, since they are the records someone files.
func TestDocumentsAreStamped(t *testing.T) {
	api := ncfAPI(t)
	env := ncfEnv(api.env())
	env.Now = func() time.Time { return fixedNow }
	plan := savePlan(t, api, writeDesired(t, desiredFixture))
	r := runCLI(t, env, "verify", "--plan", plan)
	doc := decode[VerifyDoc](t, r.stdout, "prolexic.verify.v1")
	if doc.GeneratedAt != fixedNow.UTC().Format(time.RFC3339) || doc.Prolexic == "" || doc.AccountID != "A-EXAMPLE" {
		t.Errorf("generatedAt %q, prolexic %q, accountId %q", doc.GeneratedAt, doc.Prolexic, doc.AccountID)
	}
}

// A blanked alias-version read (an empty 200, a 204, {} or an HTML page from
// a proxy) must fail the plan, never read as an empty alias: that would plan
// to drop every entry in the file past the removal limit.
func TestPlanFailsOnABlankedVersionRead(t *testing.T) {
	for name, answer := range map[string]func(http.ResponseWriter){
		"empty 200": func(w http.ResponseWriter) { w.WriteHeader(200) },
		"204":       func(w http.ResponseWriter) { w.WriteHeader(204) },
		"{}":        func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/json"); w.Write([]byte(`{}`)) },
		"html": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html>login</html>`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := ncfAPI(t)
			api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
				if strings.Contains(r.URL.Path, "/aliases/101/versions/") {
					answer(w)
					return true
				}
				return false
			}
			r := runCLI(t, ncfEnv(api.env()), "plan", "--file", writeDesired(t, desiredFixture))
			if r.code != exitCode(apperr.Upstream) {
				t.Errorf("exit = %d, want 5: %s%s", r.code, r.stdout, r.stderr)
			}
		})
	}
}

// A reviewed plan applies only with the file it was made from, for its
// account: another file could match live and exit 0 with the change unapplied.
func TestApplyPlanRefusesAnotherFileOrAccount(t *testing.T) {
	api, _ := ncfAPIState(t)
	desired := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", desired, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r")
	saved := filepath.Join(t.TempDir(), "plan.json")
	if r := runCLI(t, ncfEnv(api.env()), "plan", "--file", desired, "--out", saved); r.code != 0 {
		t.Fatalf("plan: %s", r.stderr)
	}
	env := ncfEnv(api.env())
	read := env.Getenv
	env.Getenv = func(k string) string { return read(strings.Replace(k, "AKAMAI_WRITE_", "AKAMAI_", 1)) }

	other := writeDesired(t, desiredFixture) // matches live: nothing pending
	if r := runCLI(t, env, "apply", "--file", other, "--plan", saved); r.code != exitCode(apperr.Validation) || !strings.Contains(r.stderr, "the plan was made from") {
		t.Errorf("another file: exit %d: %s", r.code, r.stderr)
	}
	b, _ := os.ReadFile(saved)
	os.WriteFile(saved, []byte(strings.Replace(string(b), `"accountId": "A-EXAMPLE"`, `"accountId": "B-OTHER"`, 1)), 0o600)
	if r := runCLI(t, env, "apply", "--file", desired, "--plan", saved); r.code != exitCode(apperr.Validation) || !strings.Contains(r.stderr, "B-OTHER") {
		t.Errorf("another account: exit %d: %s", r.code, r.stderr)
	}
}

// plan --out never destroys something: the desired file, a symlink's
// target, or a directory.
func TestPlanOutRefusesDangerousPaths(t *testing.T) {
	api := ncfAPI(t)
	desired := writeDesired(t, desiredFixture)
	dir := t.TempDir()
	link := filepath.Join(dir, "link.json")
	os.Symlink(desired, link)
	for name, out := range map[string]string{"the desired file": desired, "a symlink": link, "a directory": dir} {
		r := runCLI(t, ncfEnv(api.env()), "plan", "--file", desired, "--out", out)
		if r.code != exitCode(apperr.Usage) {
			t.Errorf("%s: exit %d: %s", name, r.code, r.stderr)
		}
	}
	if readFile(t, desired) != desiredFixture {
		t.Error("the desired file was changed")
	}
}
