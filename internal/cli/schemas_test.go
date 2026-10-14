package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite schemas/ from the Go types")

const schemaDir = "../../schemas"

// TestSchemas fails the build when a Go type and its published schema drift
// apart. Run `make schemas` after changing a document type on purpose.
func TestSchemas(t *testing.T) {
	want, err := Schemas()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.MkdirAll(schemaDir, 0o755); err != nil {
			t.Fatal(err)
		}
		old, _ := filepath.Glob(filepath.Join(schemaDir, "*.json"))
		for _, p := range old {
			os.Remove(p)
		}
		for id, b := range want {
			if err := os.WriteFile(filepath.Join(schemaDir, id+".json"), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for id, b := range want {
		got, err := os.ReadFile(filepath.Join(schemaDir, id+".json"))
		if err != nil {
			t.Errorf("%s: no committed schema (run make schemas): %v", id, err)
			continue
		}
		if !bytes.Equal(got, b) {
			t.Errorf("%s: schema drifted from its Go type (run make schemas and review the diff)", id)
		}
	}
	files, _ := filepath.Glob(filepath.Join(schemaDir, "*.json"))
	for _, p := range files {
		id := strings.TrimSuffix(filepath.Base(p), ".json")
		if _, ok := want[id]; !ok {
			t.Errorf("%s: committed schema has no Go type (run make schemas)", p)
		}
	}
}

func TestDocumentSchemaIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range documents() {
		id := d.SchemaID()
		if seen[id] || !strings.HasPrefix(id, "prolexic.") || !strings.HasSuffix(id, ".v1") {
			t.Errorf("bad or duplicate schema id %q", id)
		}
		seen[id] = true
	}
}
