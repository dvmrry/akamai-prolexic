package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestCommandTree walks the whole tree, so a new command can't skip the
// conventions that generated docs and tool schemas rely on: every command has
// a summary, runs, declares its flags (no DisableFlagParsing) and says how
// many positionals it takes (cobra.NoArgs unless it takes some), and every
// subcommand is reachable by its path.
func TestCommandTree(t *testing.T) {
	a := &app{env: Env{Getenv: func(string) string { return "" }}}
	root := a.root()

	leaves := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		if c.DisableFlagParsing {
			t.Errorf("%s: DisableFlagParsing (flags must be declared on the command)", path)
		}
		if strings.TrimSpace(c.Short) == "" {
			t.Errorf("%s: empty Short", path)
		}
		if c.RunE == nil {
			t.Errorf("%s: no RunE", path)
		}
		if c.Args == nil {
			t.Errorf("%s: no Args (use cobra.NoArgs unless it takes positionals)", path)
		}
		subs := c.Commands()
		if len(subs) == 0 {
			if c != root {
				leaves++
			}
			return
		}
		for _, s := range subs {
			found, _, err := root.Find(strings.Fields(s.CommandPath())[1:])
			if err != nil || found != s {
				t.Errorf("%s: not reachable from the root (found %v, err %v)", s.CommandPath(), found, err)
			}
			walk(s)
		}
	}
	walk(root)
	if leaves < 20 {
		t.Errorf("only %d leaves: the tree is not what it should be", leaves)
	}
}
