package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// listVar registers a repeatable, comma-separated list flag. Unlike pflag's
// StringSliceVar it trims each item and drops empty ones, so
// `--customer "a, b"` means a and b, not a and " b".
func listVar(f *pflag.FlagSet, p *[]string, name, usage string) {
	f.Var((*listValue)(p), name, usage)
}

type listValue []string

func (l *listValue) String() string { return strings.Join(*l, ",") }

func (l *listValue) Type() string { return "strings" }

func (l *listValue) Set(s string) error {
	added := false
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
			added = true
		}
	}
	if !added {
		// An empty value must not quietly mean "no filter" (every name).
		return fmt.Errorf("empty value")
	}
	return nil
}
