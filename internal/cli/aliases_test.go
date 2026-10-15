package cli

import (
	"strings"
	"testing"
)

func TestAliasesList(t *testing.T) {
	api := ncfAPI(t)
	r := runCLI(t, ncfEnv(api.env()), "aliases", "list")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[AliasesDoc](t, r.stdout, "prolexic.aliases.v1")
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

func TestAliasesListEditable(t *testing.T) {
	api := ncfAPI(t)
	r := runCLI(t, ncfEnv(api.env()), "aliases", "list", "--editable")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[AliasesDoc](t, r.stdout, "prolexic.aliases.v1")
	if len(doc.Aliases) != 1 || doc.Aliases[0].Name != "block-v4" {
		t.Errorf("aliases = %+v", doc.Aliases)
	}
	r = runCLI(t, ncfEnv(api.env()), "aliases", "list", "--format", "text")
	if !strings.Contains(r.stdout, "akamai-threats") || !strings.Contains(r.stdout, "NAME") {
		t.Errorf("text:\n%s", r.stdout)
	}
}
