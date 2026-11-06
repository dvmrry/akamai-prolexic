package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// docsDir is the committed reference, relative to this package.
const docsDir = "../../../docs/cli"

// TestDocsCurrent fails when docs/cli/ differs from what the command tree
// generates; run `make docs` and commit the result.
func TestDocsCurrent(t *testing.T) {
	fresh := t.TempDir()
	if err := generate(fresh); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Glob(filepath.Join(fresh, "*.md"))
	if err != nil || len(want) == 0 {
		t.Fatalf("generated nothing (%v)", err)
	}
	for _, p := range want {
		name := filepath.Base(p)
		w, _ := os.ReadFile(p)
		got, err := os.ReadFile(filepath.Join(docsDir, name))
		switch {
		case err != nil:
			t.Errorf("%s: not committed (run make docs): %v", name, err)
		case !bytes.Equal(got, w):
			t.Errorf("%s: stale (run make docs and commit the result)", name)
		}
	}
	have, _ := filepath.Glob(filepath.Join(docsDir, "*.md"))
	for _, p := range have {
		if _, err := os.Stat(filepath.Join(fresh, filepath.Base(p))); err != nil {
			t.Errorf("%s: no longer generated (run make docs)", filepath.Base(p))
		}
	}
}
