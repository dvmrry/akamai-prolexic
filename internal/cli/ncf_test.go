package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

// ncfEnv is env with a fixed date and the documentation ranges allowed,
// since synthetic fixtures must use them.
func ncfEnv(env Env) Env {
	env.Now = func() time.Time { return time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC) }
	env.Bogons = slices.DeleteFunc(slices.Clone(ncf.Bogons), func(p netip.Prefix) bool {
		return slices.Contains(ncf.DocumentationRanges, p)
	})
	return env
}

const desiredFixture = `{
  "accountId": "A-EXAMPLE",
  "aliases": [
    {
      "entries": [
        "192.0.2.0/25",
        "198.51.100.7/32"
      ],
      "id": 101,
      "name": "block-v4",
      "role": "deny",
      "type": "SOURCE"
    }
  ],
  "ownSpace": {
    "aliases": [],
    "prefixes": [
      "203.0.113.0/24"
    ]
  },
  "schema": "prolexic.desired.v1"
}
`

func writeDesired(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestValidate(t *testing.T) {
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(Env{}), "validate", "--file", p)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	if doc := decode[ValidateDoc](t, r.stdout, "prolexic.validate.v1"); !doc.Valid || len(doc.Findings) != 0 {
		t.Errorf("doc = %+v", doc)
	}

	bad := writeDesired(t, strings.Replace(desiredFixture, "198.51.100.7/32", "203.0.113.7/32", 1))
	r = runCLI(t, ncfEnv(Env{}), "validate", "--file", bad)
	doc := decode[ValidateDoc](t, r.stdout, "prolexic.validate.v1")
	if r.code != int(apperr.Validation) || doc.Valid || doc.Findings[0].Code != "own_space" {
		t.Errorf("exit = %d, doc = %+v", r.code, doc)
	}
}

func TestValidateNeedsNoCredentials(t *testing.T) {
	p := writeDesired(t, desiredFixture)
	env := ncfEnv(Env{})
	env.Getenv = func(k string) string {
		if strings.HasPrefix(k, "AKAMAI_") {
			t.Errorf("validate read credential variable $%s", k)
		}
		return ""
	}
	if r := runCLI(t, env, "validate", "--file", p); r.code != 0 {
		t.Errorf("exit = %d: %s", r.code, r.stderr)
	}
}

func TestFmt(t *testing.T) {
	messy := strings.ReplaceAll(desiredFixture, "  ", "\t")
	p := writeDesired(t, messy)
	r := runCLI(t, ncfEnv(Env{}), "fmt", "--file", p, "--check")
	if r.code != int(apperr.Validation) || readFile(t, p) != messy {
		t.Errorf("--check: exit = %d, and it must not write", r.code)
	}
	r = runCLI(t, ncfEnv(Env{}), "fmt", "--file", p)
	if r.code != 0 || readFile(t, p) != desiredFixture {
		t.Errorf("fmt: exit = %d, file:\n%s", r.code, readFile(t, p))
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want the original 0640", st.Mode().Perm())
	}
	if r := runCLI(t, ncfEnv(Env{}), "validate", "--file", p); r.code != 0 {
		t.Errorf("validate after fmt: exit = %d", r.code)
	}
}

func TestAddWritesOneCanonicalEntry(t *testing.T) {
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "198.51.100.64/26", "geo::de", "--ticket", "SEC-9", "--reason", "scanning", "--expires", "2027-01-31")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ChangeDoc](t, r.stdout, "prolexic.change.v1")
	if !doc.Written || len(doc.Entries) != 2 || doc.Entries[1].CIDR != "GEO::DE" || doc.Entries[0].Added != "2026-10-14" {
		t.Errorf("doc = %+v", doc)
	}
	want := strings.Replace(desiredFixture, `        "198.51.100.7/32"
`, `        "198.51.100.7/32",
        {
          "added": "2026-10-14",
          "cidr": "198.51.100.64/26",
          "expires": "2027-01-31",
          "reason": "scanning",
          "ticket": "SEC-9"
        },
        {
          "added": "2026-10-14",
          "cidr": "GEO::DE",
          "expires": "2027-01-31",
          "reason": "scanning",
          "ticket": "SEC-9"
        }
`, 1)
	if got := readFile(t, p); got != want {
		t.Errorf("file:\n%s", got)
	}
}

func TestAddWritesNothingOnAFinding(t *testing.T) {
	tests := map[string][]string{
		"host bits":                             {"192.0.2.129/24"},
		"own space":                             {"203.0.113.0/25"},
		"already present":                       {"198.51.100.7"},
		"contained (warning on an added entry)": {"192.0.2.0/26"},
		"one bad of two":                        {"198.51.100.200", "10.0.0.0/8"},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			p := writeDesired(t, desiredFixture)
			args := append([]string{"add", "--file", p, "--ticket", "SEC-9", "--reason", "r", "block-v4"}, entries...)
			r := runCLI(t, ncfEnv(Env{}), args...)
			doc := decode[ChangeDoc](t, r.stdout, "prolexic.change.v1")
			if r.code != int(apperr.Validation) || doc.Written || readFile(t, p) != desiredFixture {
				t.Errorf("exit = %d, doc = %+v", r.code, doc)
			}
		})
	}
}

func TestAddUsage(t *testing.T) {
	p := writeDesired(t, desiredFixture)
	for _, args := range [][]string{
		{"add", "--file", p, "block-v4", "198.51.100.9", "--reason", "r"},  // no ticket
		{"add", "--file", p, "block-v4", "--ticket", "T", "--reason", "r"}, // no entry
		{"add", "--file", p, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r", "--expires", "soon"},
	} {
		if r := runCLI(t, ncfEnv(Env{}), args...); r.code != int(apperr.Usage) {
			t.Errorf("%v: exit = %d", args, r.code)
		}
	}
}

func TestRemove(t *testing.T) {
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(Env{}), "remove", "--file", p, "block-v4", "198.51.100.7", "--ticket", "SEC-10")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ChangeDoc](t, r.stdout, "prolexic.change.v1")
	if !doc.Written || doc.Ticket != "SEC-10" || doc.Entries[0].CIDR != "198.51.100.7/32" {
		t.Errorf("doc = %+v", doc)
	}
	if strings.Contains(readFile(t, p), "198.51.100.7") {
		t.Error("entry still in the file")
	}

	r = runCLI(t, ncfEnv(Env{}), "remove", "--file", p, "block-v4", "198.51.100.8", "--ticket", "SEC-10")
	if r.code != int(apperr.Validation) {
		t.Errorf("removing an absent entry: exit = %d", r.code)
	}
}

// ncfAPI is a fake account over NCF v1 and Analytics.
func ncfAPI(t *testing.T) *fakeAPI {
	api := newFakeAPI(t)
	api.json("GET /network-cloud-firewall/v1/acls/aliases", 200, `[
	  {"aliasId": 101, "aliasName": "block-v4", "aliasListType": "SOURCE", "ipVersion": "V4", "accountId": "A-EXAMPLE",
	   "isCustomerEditable": true, "entriesCount": 2, "entries": ["192.0.2.0/25", "198.51.100.7"]},
	  {"aliasId": 900, "aliasName": "akamai-threats", "aliasListType": "BIG", "ipVersion": "V4", "accountId": "A-EXAMPLE",
	   "isCustomerEditable": false, "entriesCount": 200000}
	]`)
	api.json("GET /network-cloud-firewall/v1/acls/aliases/101", 200, `{"aliasId": 101, "aliasName": "block-v4",
	  "aliasListType": "SOURCE", "ipVersion": "V4", "accountId": "A-EXAMPLE", "isCustomerEditable": true,
	  "entriesCount": 2, "entries": ["192.0.2.0/25", "198.51.100.7"]}`)
	api.json("GET /prolexic-analytics/v2/customer/names", 200, `{"customerNames":[{"name":"example-a","contractId":"C-EXAMPLE","accountName":"Example","inUse":true}]}`)
	api.json("GET /prolexic-analytics/v2/metric-types/example-a", 200, `{"currentContract":"example-a","status":true,
	  "data":{"fbm":{"metrics":{"bandwidth":{"subnets":["198.51.100.128/25"]},"packets":{"subnets":[]}}}}}`)
	return api
}

func TestPlanAgainstV1(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if doc.Changes || !doc.OwnSpaceAnalytics || len(doc.Aliases) != 1 || doc.Aliases[0].Unchanged != 2 || doc.Aliases[0].VersionsRemaining != nil {
		t.Errorf("doc = %+v", doc)
	}
	for _, c := range api.calls {
		if strings.HasSuffix(c.Path, "/aliases/900") {
			t.Error("plan fetched a managed alias's entries")
		}
	}
}

func TestPlanDriftAndOwnSpaceFromAnalytics(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r")
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p, "--exit-code")
	doc := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if r.code != int(apperr.Drift) || !doc.Changes || len(doc.Aliases[0].Add) != 1 || !strings.HasPrefix(doc.Digest, "sha256:") {
		t.Errorf("exit = %d, doc = %+v", r.code, doc)
	}

	runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "198.51.100.200", "--ticket", "T", "--reason", "r")
	r = runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	doc = decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if r.code != int(apperr.Validation) || len(doc.Findings) != 1 || doc.Findings[0].Code != "own_space" ||
		!strings.Contains(doc.Findings[0].Message, "analytics example-a/example-a") {
		t.Errorf("exit = %d, findings = %+v", r.code, doc.Findings)
	}
}

func TestApplyOnV1IsUnsupportedAndWritesNothing(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r")
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	digest := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1").Digest

	env := ncfEnv(api.env())
	read := env.Getenv
	env.Getenv = func(k string) string { // the write section resolves to the same fake
		return read(strings.Replace(k, "AKAMAI_WRITE_", "AKAMAI_", 1))
	}
	r = runCLI(t, env, "apply", "--file", p, "--expect-digest", digest)
	if r.code != int(apperr.NotFound) || !strings.Contains(r.stderr, "NCF v2") {
		t.Errorf("exit = %d: %s", r.code, r.stderr)
	}
	for _, c := range api.calls {
		if c.Method != "GET" && !strings.Contains(c.Path, "prolexic-analytics") {
			t.Errorf("apply sent %s %s", c.Method, c.Path)
		}
	}
}

func TestApplyNeedsWriteCredentials(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(api.env()), "apply", "--file", p, "--expect-digest", "sha256:x")
	if r.code != int(apperr.Credentials) {
		t.Errorf("exit = %d: %s", r.code, r.stderr)
	}
	r = runCLI(t, ncfEnv(api.env()), "apply", "--file", p)
	if r.code != int(apperr.Usage) {
		t.Errorf("no digest: exit = %d", r.code)
	}
}
