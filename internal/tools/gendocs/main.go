// Command gendocs writes the Markdown CLI reference, one file per command,
// from the Cobra tree: `make docs` runs it, and TestDocsCurrent fails when
// docs/cli/ is stale.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/dvmrry/akamai-prolexic/internal/cli"
)

func main() {
	dir := "docs/cli"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := generate(dir); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}

// generate replaces the Markdown files of dir with the current reference.
func generate(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	old, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		return err
	}
	for _, p := range old {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	root := cli.CommandTree()
	noTag(root)
	return doc.GenMarkdownTree(root, dir)
}

// noTag drops the "Auto generated" footer, which carries the date and would
// make the output differ from run to run.
func noTag(c *cobra.Command) {
	c.DisableAutoGenTag = true
	for _, s := range c.Commands() {
		noTag(s)
	}
}
