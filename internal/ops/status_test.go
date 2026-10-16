package ops

import (
	"strings"
	"testing"
)

func TestStatusDocText(t *testing.T) {
	// The marker needs an alias with a pending activation, so render a
	// document directly.
	d := &StatusDoc{Aliases: []StatusAlias{
		{Name: "pending", ActiveVersion: "V9", ProdVersion: "V8"},
		{Name: "fine", ActiveVersion: "V4", ProdVersion: "V4"},
		{Name: "unused", ActiveVersion: "V1", ProdVersion: ""}, // no deployed rule uses it: nothing is pending
	}}
	var b strings.Builder
	if err := d.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(b.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "pending"):
			if !strings.Contains(line, "ACTIVATION PENDING") {
				t.Errorf("pending: %q", line)
			}
		case strings.HasPrefix(line, "unused"):
			if strings.Contains(line, "PENDING") || !strings.Contains(line, "not in production") {
				t.Errorf("unused: %q", line)
			}
		case strings.HasPrefix(line, "fine"):
			if strings.Contains(line, "PENDING") || strings.Contains(line, "LOW") {
				t.Errorf("fine: %q", line)
			}
		}
	}
}
