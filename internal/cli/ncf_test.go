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

// ncfAPI is a fake account over NCF v2 and Analytics.
func ncfAPI(t *testing.T) *fakeAPI {
	api, _ := ncfAPIState(t)
	return api
}

// ncfAPIState is ncfAPI, also returning the stateful NCF fake.
func ncfAPIState(t *testing.T) (*fakeAPI, *fakeNCF) {
	api := newFakeAPI(t)
	ncfState := api.ncfV2(
		editableAlias(101, "block-v4", "V4", "192.0.2.0/25", "198.51.100.7"),
		managedAlias(900, "akamai-threats", 200000),
	)
	api.json("GET /prolexic-analytics/v2/customer/names", 200, `{"customerNames":[{"name":"example-a","contractId":"C-EXAMPLE","accountName":"Example","inUse":true},{"name":"example-old","contractId":"C-EXAMPLE","accountName":"Example","inUse":false}]}`)
	api.json("GET /prolexic-analytics/v2/metric-types/example-old", 200, `{"currentContract":"example-old","status":true,
	  "data":{"fbm":{"metrics":{"bandwidth":{"subnets":["192.0.2.192/26"]},"packets":{"subnets":[]}}}}}`)
	api.json("GET /prolexic-analytics/v2/metric-types/example-a", 200, `{"currentContract":"example-a","status":true,
	  "data":{"fbm":{"metrics":{"bandwidth":{"subnets":["198.51.100.128/25"]},"packets":{"subnets":[]}}}}}`)
	// Our routers announce from AS 64500 (a documentation ASN).
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 200, `[{"asn":64500,"dataCenter":"DC-A","routerName":"edge-1",
	  "akamaiGreEndpointIpv4":"192.0.2.1","customerGreEndpointIpv4":"198.51.100.1","akamaiBgpPeerIpv4":"192.0.2.5",
	  "customerBgpPeerIpv4":"192.0.2.6","healthIpv4":"UP"}]`)
	return api, ncfState
}

func TestPlanAgainstV2(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if doc.Changes || !doc.OwnSpaceAnalytics || len(doc.Aliases) != 1 || doc.Aliases[0].Unchanged != 2 || doc.Aliases[0].ActiveVersion != "V1" {
		t.Errorf("doc = %+v", doc)
	}
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/aliases/900") {
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

func TestApplyThroughTheCLI(t *testing.T) {
	api, ncfState := ncfAPIState(t)
	p := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "198.51.100.9", "--ticket", "T", "--reason", "r")
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	plan := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if plan.Aliases[0].ActiveVersion != "V1" {
		t.Fatalf("planned active version = %q", plan.Aliases[0].ActiveVersion)
	}

	env := ncfEnv(api.env())
	read := env.Getenv
	env.Getenv = func(k string) string { // the write section resolves to the same fake
		return read(strings.Replace(k, "AKAMAI_WRITE_", "AKAMAI_", 1))
	}
	r = runCLI(t, env, "apply", "--file", p, "--expect-digest", plan.Digest, "--interval", "1ms", "--timeout", "5s")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ApplyDoc](t, r.stdout, "prolexic.apply.v1")
	if doc.Result == nil || len(doc.Result.Aliases) != 1 || doc.Result.Aliases[0].Status != ncf.StatusDeployed || doc.Result.Aliases[0].Version != "V2" {
		t.Errorf("result = %+v", doc.Result)
	}

	ncfState.mu.Lock()
	defer ncfState.mu.Unlock()
	if len(ncfState.Creates) != 1 {
		t.Fatalf("creates = %v", ncfState.Creates)
	}
	if c := ncfState.Creates[0]; c["isActive"] != false || c["sourceVersion"] != "V1" {
		t.Errorf("create body = %v; want isActive false and sourceVersion V1", c)
	}
	if !slices.Equal(ncfState.Activated, []string{"101/V2"}) {
		t.Errorf("activations = %v", ncfState.Activated)
	}
	if a := ncfState.aliases[0]; a.Prod != 2 || a.Active != 2 {
		t.Errorf("alias active %d, prod %d; want both 2", a.Active, a.Prod)
	}
	var writes []string
	for _, c := range api.calls {
		if c.Method != "GET" && !strings.Contains(c.Path, "prolexic-analytics") {
			writes = append(writes, c.Method+" "+c.Path)
		}
	}
	want := []string{
		"POST /network-cloud-firewall/v2/aliases/101/versions",
		"PATCH /network-cloud-firewall/v2/aliases/101/versions/V2/activate",
	}
	if !slices.Equal(writes, want) {
		t.Errorf("writes = %v", writes)
	}
	noManagedFetch(t, api)
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

func TestPlanOwnSpaceIncludesCustomerNamesNotInUse(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "192.0.2.200", "--ticket", "T", "--reason", "r")
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	doc := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if r.code != int(apperr.Validation) || len(doc.Findings) != 1 || !strings.Contains(doc.Findings[0].Message, "analytics example-old/") {
		t.Errorf("exit = %d, findings = %+v", r.code, doc.Findings)
	}
}

func TestPlanRejectsOurOwnASNFromBGPSessions(t *testing.T) {
	api := ncfAPI(t)
	p := writeDesired(t, desiredFixture)
	runCLI(t, ncfEnv(Env{}), "add", "--file", p, "block-v4", "ASN::64500", "--ticket", "T", "--reason", "r")
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	doc := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if r.code != int(apperr.Validation) || len(doc.Findings) != 1 || doc.Findings[0].Code != "own_space" ||
		!strings.Contains(doc.Findings[0].Message, "our own AS (analytics example-a/DC-A)") {
		t.Errorf("exit = %d, findings = %+v", r.code, doc.Findings)
	}
}

func TestPlanCustomerNameWithoutRoutedHasNoASNs(t *testing.T) {
	api := ncfAPI(t)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 404, `{"errorCode":"NOT_FOUND","message":"no routed service"}`)
	p := writeDesired(t, desiredFixture)
	r := runCLI(t, ncfEnv(api.env()), "plan", "--file", p)
	doc := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	if r.code != 0 || !slices.ContainsFunc(doc.Findings, func(f ncf.Finding) bool { return f.Code == "own_space_asn_unknown" }) {
		t.Errorf("exit = %d, findings = %+v; a 404 must be visible", r.code, doc.Findings)
	}
}
