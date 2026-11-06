package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

func TestAliasesList(t *testing.T) {
	api := ncfAPI(t)
	r := runCLI(t, ncfEnv(api.env()), "aliases", "list")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ops.AliasesDoc](t, r.stdout, "prolexic.aliases.v1")
	if len(doc.Aliases) != 2 {
		t.Fatalf("aliases = %+v", doc.Aliases)
	}
	m, b := doc.Aliases[0], doc.Aliases[1]
	if m.Name != "akamai-threats" || m.Editable || m.EntriesCount != 200000 || !m.InUse {
		t.Errorf("managed = %+v", m)
	}
	if b.Name != "block-v4" || b.ID != 101 || b.Type != "SOURCE" || b.IPVersion != "V4" || !b.Editable ||
		b.ActiveVersion != "V1" || b.ProdVersion != "V1" || b.EntriesCount != 2 || len(b.ProdRuleIndexes) != 1 || b.ProdRuleIndexes[0] != 1 {
		t.Errorf("block-v4 = %+v", b)
	}
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/versions") {
			t.Errorf("list fetched %s; it must only list", c.Path)
		}
	}
}

func TestAliasesShow(t *testing.T) {
	api, state := ncfAPIState(t)
	// A second version with entries in a non-canonical order and spelling.
	state.aliases[0].Versions = append(state.aliases[0].Versions, []string{"2001:db8::/32", "ASN::64501", "198.51.100.7", "GEO::us", "192.0.2.128/25", "not an entry"})
	r := runCLI(t, ncfEnv(api.env()), "aliases", "show", "--name", "block-v4")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ops.AliasDoc](t, r.stdout, "prolexic.alias.v1")
	if doc.Version != "V1" || !doc.Active || doc.Managed || len(doc.Entries) != 2 || doc.Entries[0] != "192.0.2.0/25" || doc.Entries[1] != "198.51.100.7/32" {
		t.Errorf("default = %+v", doc)
	}
	r = runCLI(t, ncfEnv(api.env()), "aliases", "show", "--id", "101", "--version", "V2")
	doc = decode[ops.AliasDoc](t, r.stdout, "prolexic.alias.v1")
	want := []string{"192.0.2.128/25", "198.51.100.7/32", "2001:db8::/32", "GEO::US", "ASN::64501", "not an entry"}
	if doc.Version != "V2" || doc.Active || strings.Join(doc.Entries, ",") != strings.Join(want, ",") {
		t.Errorf("V2 = %+v", doc)
	}
}

func TestAliasesShowManagedOnlyWhenNamed(t *testing.T) {
	api := ncfAPI(t)
	api.json("GET /network-cloud-firewall/v2/aliases/900/versions/V1", 200, `{"aliasId":900,"version":"V1","isActive":true,"entries":["203.0.113.0/24"]}`)
	r := runCLI(t, ncfEnv(api.env()), "aliases", "show", "--name", "akamai-threats", "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "Akamai-managed") || !strings.Contains(r.stdout, "203.0.113.0/24") {
		t.Errorf("exit %d:\n%s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ops.AliasDoc](t, runCLI(t, ncfEnv(api.env()), "aliases", "show", "--id", "900").stdout, "prolexic.alias.v1")
	if !doc.Managed || len(doc.Entries) != 1 {
		t.Errorf("doc = %+v", doc)
	}
}

func TestAliasesShowUsage(t *testing.T) {
	api := ncfAPI(t)
	for _, args := range [][]string{{"aliases", "show"}, {"aliases", "show", "--name", "block-v4", "--id", "101"}} {
		if r := runCLI(t, ncfEnv(api.env()), args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d", args, r.code)
		}
	}
	if r := runCLI(t, ncfEnv(api.env()), "aliases", "show", "--name", "nope"); r.code != exitCode(apperr.NotFound) {
		t.Errorf("unknown alias: exit = %d", r.code)
	}
}

func TestAliasesVersionsPagesAndSorts(t *testing.T) {
	api := ncfAPI(t)
	api.routes["GET /network-cloud-firewall/v2/aliases/101/versions"] = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "0" {
			w.Write([]byte(`{"content":[{"version":"V2","isActive":false,"entriesCount":3,"comments":"prolexic apply abc123","sourceVersion":"V1","updatedBy":"example-user"},
			  {"version":"V10","isActive":true,"entriesCount":4,"comments":"","sourceVersion":"V2"}],"last":false,"totalPages":2}`))
			return
		}
		w.Write([]byte(`{"content":[{"version":"V1","isActive":false,"entriesCount":2}],"last":true,"totalPages":2}`))
	}
	r := runCLI(t, ncfEnv(api.env()), "aliases", "versions", "--name", "block-v4")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ops.AliasVersionsDoc](t, r.stdout, "prolexic.alias-versions.v1")
	var got []string
	for _, v := range doc.Versions {
		got = append(got, v.Version)
	}
	if strings.Join(got, ",") != "V10,V2,V1" {
		t.Fatalf("versions = %v", got)
	}
	if v := doc.Versions[1]; v.Comment != "prolexic apply abc123" || v.SourceVersion != "V1" || v.EntriesCount != 3 || !doc.Versions[0].Active {
		t.Errorf("V2 = %+v", v)
	}
	if r := runCLI(t, ncfEnv(api.env()), "aliases", "versions", "--id", "101", "--format", "text"); !strings.Contains(r.stdout, "prolexic apply abc123") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestAliasesListEditable(t *testing.T) {
	api := ncfAPI(t)
	r := runCLI(t, ncfEnv(api.env()), "aliases", "list", "--editable")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.AliasesDoc](t, r.stdout, "prolexic.aliases.v1")
	if len(doc.Aliases) != 1 || doc.Aliases[0].Name != "block-v4" {
		t.Errorf("aliases = %+v", doc.Aliases)
	}
	r = runCLI(t, ncfEnv(api.env()), "aliases", "list", "--format", "text")
	if !strings.Contains(r.stdout, "akamai-threats") || !strings.Contains(r.stdout, "NAME") {
		t.Errorf("text:\n%s", r.stdout)
	}
}
