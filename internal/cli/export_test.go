package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// exportAPI is a fake account with two editable aliases (a deny-list
// candidate and an allow-list candidate: IPv6, entries in a non-canonical
// spelling) and a managed one.
func exportAPI(t *testing.T) *fakeAPI {
	api := newFakeAPI(t)
	api.ncfV2(
		editableAlias(101, "block-v4", "V4", "198.51.100.7", "192.0.2.0/25", "geo::de"),
		editableAlias(102, "allow-v6", "V6", "2001:db8:0:0::1", "2001:db8:1::/48"),
		managedAlias(900, "akamai-threats", 200000),
	)
	return api
}

func noManagedFetch(t *testing.T, api *fakeAPI) {
	t.Helper()
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/aliases/900") {
			t.Error("export fetched a managed alias's entries")
		}
	}
}

func TestExportBootstrap(t *testing.T) {
	api := exportAPI(t)
	p := filepath.Join(t.TempDir(), "desired.json")
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if !doc.Created || !doc.Written || len(doc.Aliases) != 2 || doc.Aliases[0].Name != "allow-v6" ||
		strings.Join(doc.Aliases[1].Added, " ") != "192.0.2.0/25 198.51.100.7/32 GEO::DE" || len(doc.Aliases[1].Removed) != 0 {
		t.Errorf("doc = %+v", doc)
	}
	noManagedFetch(t, api)
	got := readFile(t, p)
	for _, want := range []string{`"accountId": "A-EXAMPLE"`, `"role": "deny"`, `"schema": "prolexic.desired.v1"`,
		`"2001:db8::1/128"`, `"198.51.100.7/32"`, `"GEO::DE"`, `"prefixes": []`} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "akamai-threats") {
		t.Error("managed alias exported")
	}
	// Structurally valid, and already canonical.
	if r := runCLI(t, ncfEnv(Env{}), "fmt", "--file", p, "--check"); r.code != 0 {
		t.Errorf("not canonical: exit = %d", r.code)
	}
	if r := runCLI(t, ncfEnv(Env{}), "validate", "--file", p); r.code != 0 {
		t.Errorf("validate: exit = %d: %s", r.code, r.stdout)
	}

	// The deployed rules decide the role where one references the alias:
	// rule 1 denies block-v4 as a source, so --role allow can't override it.
	p2 := filepath.Join(t.TempDir(), "allow.json")
	runCLI(t, ncfEnv(api.env()), "export", "--file", p2, "--role", "allow")
	if !strings.Contains(readFile(t, p2), "\"name\": \"block-v4\",\n      \"id\": 101,\n      \"type\": \"SOURCE\",\n      \"role\": \"deny\"") {
		t.Errorf("--role allow:\n%s", readFile(t, p2))
	}
	r = runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	doc = decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if r.code != 0 || doc.Created || doc.Written || readFile(t, p) != got {
		t.Errorf("second run: exit %d, doc %+v", r.code, doc)
	}
}

func TestExportBootstrapAccountProblemsWriteNothing(t *testing.T) {
	for name, aliases := range map[string]string{
		"disagree": `[{"aliasId":1,"aliasName":"a","aliasType":"SOURCE","accountId":"A-EXAMPLE","isCustomerEditable":true},
		              {"aliasId":2,"aliasName":"b","aliasType":"SOURCE","accountId":"A-OTHER","isCustomerEditable":true}]`,
		"none":     `[{"aliasId":1,"aliasName":"a","aliasType":"SOURCE","isCustomerEditable":true}]`,
		"no alias": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t)
			api.json("GET /network-cloud-firewall/v2/aliases", 200, aliases)
			p := filepath.Join(t.TempDir(), "desired.json")
			r := runCLI(t, ncfEnv(api.env()), "export", "--file", p)
			if _, err := os.Stat(p); r.code != exitCode(apperr.Validation) || err == nil {
				t.Errorf("exit = %d, file written: %v", r.code, err == nil)
			}
		})
	}
}

const exportExisting = `{
  "$schema": "https://example.invalid/desired.json",
  "accountId": "A-EXAMPLE",
  "aliases": [
    {
      "entries": [
        {
          "added": "2026-01-02",
          "cidr": "192.0.2.0/25",
          "reason": "scanner",
          "ticket": "SEC-1"
        },
        {
          "cidr": "198.51.100.9/32",
          "ticket": "SEC-2"
        }
      ],
      "id": 101,
      "name": "block-v4",
      "role": "allow",
      "type": "SOURCE"
    }
  ],
  "ownSpace": {
    "aliases": [
      "protected"
    ],
    "prefixes": [
      "203.0.113.0/24"
    ]
  },
  "schema": "prolexic.desired.v1"
}
`

func TestExportRefreshesOnlyNamedAliases(t *testing.T) {
	api := exportAPI(t)
	p := writeDesired(t, exportExisting)
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if doc.Created || !doc.Written || len(doc.Aliases) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
	if strings.Join(doc.Aliases[0].Added, " ") != "198.51.100.7/32 GEO::DE" || strings.Join(doc.Aliases[0].Removed, " ") != "198.51.100.9/32" {
		t.Errorf("delta = %+v", doc.Aliases[0])
	}
	got := readFile(t, p)
	for _, want := range []string{
		`"$schema": "https://example.invalid/desired.json"`, `"role": "deny"` /* from the deployed rule, not the file's allow */, `"protected"`, `"203.0.113.0/24"`,
		`"ticket": "SEC-1"`, `"reason": "scanner"`, `"added": "2026-01-02"`, `"198.51.100.7/32"`, `"GEO::DE"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "198.51.100.9") || strings.Contains(got, "SEC-2") || strings.Contains(got, "allow-v6") {
		t.Errorf("stale or unrequested content:\n%s", got)
	}
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/aliases/102") || strings.Contains(c.Path, "/aliases/900") {
			t.Errorf("fetched %s, which the file doesn't name", c.Path)
		}
	}
	if r := runCLI(t, ncfEnv(Env{}), "validate", "--file", p); r.code != 0 {
		t.Errorf("validate: exit = %d: %s", r.code, r.stdout)
	}
	// Idempotent.
	r = runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	doc = decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if doc.Written || len(doc.Aliases[0].Added) != 0 || len(doc.Aliases[0].Removed) != 0 || doc.Aliases[0].Added == nil {
		t.Errorf("second run: %+v", doc)
	}
}

func TestExportAllAppendsEditableAliases(t *testing.T) {
	api := exportAPI(t)
	p := writeDesired(t, exportExisting)
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p, "--all", "--role", "deny")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if len(doc.Aliases) != 2 || doc.Aliases[0].Name != "allow-v6" || len(doc.Aliases[0].Added) != 2 {
		t.Errorf("doc = %+v", doc)
	}
	got := readFile(t, p)
	if !strings.Contains(got, `"allow-v6"`) || !strings.Contains(got, `"role": "allow"`) || strings.Count(got, `"role": "deny"`) != 1 {
		t.Errorf("roles:\n%s", got)
	}
	noManagedFetch(t, api)
}

func TestExportRefusesAndWritesNothing(t *testing.T) {
	tests := map[string]struct {
		file string
		code apperr.Kind
	}{
		"id not live":    {strings.Replace(exportExisting, `"id": 101`, `"id": 555`, 1), apperr.Validation},
		"name mismatch":  {strings.Replace(exportExisting, `"block-v4"`, `"renamed"`, 1), apperr.Validation},
		"type mismatch":  {strings.Replace(exportExisting, `"SOURCE"`, `"DIPA"`, 1), apperr.Validation},
		"managed alias":  {strings.NewReplacer(`"id": 101`, `"id": 900`, `"block-v4"`, `"akamai-threats"`, `"SOURCE"`, `"BIG"`).Replace(exportExisting), apperr.Validation},
		"undecodable":    {strings.Replace(exportExisting, `"role"`, `"rol"`, 1), apperr.Validation},
		"unknown fields": {strings.Replace(exportExisting, `"ownSpace"`, `"extra": 1, "ownSpace"`, 1), apperr.Validation},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			api := exportAPI(t)
			p := writeDesired(t, tt.file)
			r := runCLI(t, ncfEnv(api.env()), "export", "--file", p, "--all")
			if r.code != exitCode(tt.code) || readFile(t, p) != tt.file {
				t.Errorf("exit = %d, want %s; file changed: %v", r.code, tt.code, readFile(t, p) != tt.file)
			}
			noManagedFetch(t, api)
		})
	}
}

func TestExportUnparsableLiveEntryWritesNothing(t *testing.T) {
	api := exportAPI(t)
	api.json("GET /network-cloud-firewall/v2/aliases/102/versions/V1", 200, `{"aliasId": 102, "aliasName": "allow-v6", "aliasType": "SOURCE",
	  "ipVersion": "V6", "version": "V1", "isActive": true, "entries": ["2001:db8::1", "garbage"], "entriesCount": 2}`)
	p := filepath.Join(t.TempDir(), "desired.json")
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	if _, err := os.Stat(p); r.code != exitCode(apperr.Upstream) || err == nil ||
		!strings.Contains(r.stderr, "allow-v6") || !strings.Contains(r.stderr, "garbage") {
		t.Errorf("exit = %d, written: %v, stderr: %s", r.code, err == nil, r.stderr)
	}
}

func TestExportUsage(t *testing.T) {
	api := exportAPI(t)
	for _, args := range [][]string{
		{"export"},
		{"export", "--file", filepath.Join(t.TempDir(), "d.json"), "--role", "maybe"},
	} {
		if r := runCLI(t, ncfEnv(api.env()), args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d", args, r.code)
		}
	}
}

func TestExportText(t *testing.T) {
	api := exportAPI(t)
	p := writeDesired(t, exportExisting)
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p, "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "+ block-v4 198.51.100.7/32") || !strings.Contains(r.stdout, "- block-v4 198.51.100.9/32") ||
		!strings.Contains(r.stdout, "written, 1 aliases, +2 -1") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
}

func TestExportIntoAnEmptyFileBootstraps(t *testing.T) {
	api := exportAPI(t)
	p := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(p, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	doc := decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if r.code != 0 || !doc.Created || !doc.Written {
		t.Errorf("exit = %d, doc = %+v, stderr = %s", r.code, doc, r.stderr)
	}
}

// A protected-destination alias a deployed rule uses as its destination is
// exported with role destination and declared as own space.
func TestExportDeclaresADestinationAsOwnSpace(t *testing.T) {
	api := newFakeAPI(t)
	api.ncfV2(
		editableAlias(101, "block-v4", "V4", "198.51.100.7", "192.0.2.0/25"),
		&fakeAlias{ID: 103, Name: "protected-dst", Type: "DIPA", IPVer: "V4", Editable: true, Versions: [][]string{{"203.0.113.0/26"}}, Active: 1, Prod: 1},
	)
	p := filepath.Join(t.TempDir(), "desired.json")
	r := runCLI(t, ncfEnv(api.env()), "export", "--file", p)
	doc := decode[ExportDoc](t, r.stdout, "prolexic.export.v1")
	if r.code != 0 || !slices.Equal(doc.OwnSpaceAdded, []string{"protected-dst"}) {
		t.Fatalf("exit %d, ownSpaceAdded %v: %s", r.code, doc.OwnSpaceAdded, r.stderr)
	}
	file := readFile(t, p)
	if !strings.Contains(file, `"aliases": [`+"\n      \"protected-dst\"") || !strings.Contains(file, `"role": "destination"`) || !strings.Contains(file, `"role": "deny"`) {
		t.Errorf("file:\n%s", file)
	}
	// The exported file plans clean: the declaration and the role agree with
	// the rules, so no warning and no mismatch.
	r = runCLI(t, ncfEnv(api.env()), "plan", "--file", p, "--no-analytics-own-space", "--format", "json")
	plan := decode[PlanDoc](t, r.stdout, "prolexic.plan.v1")
	for _, f := range plan.Findings {
		if f.Code != "own_space_analytics_skipped" {
			t.Errorf("finding %s: %s", f.Code, f.Message)
		}
	}
}
