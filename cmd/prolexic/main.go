// Command prolexic is a CLI for Akamai Prolexic, over the Akamai APIs.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/dvmrry/akamai-prolexic/internal/version"
)

const (
	exitSuccess = 0
	exitUsage   = 2
)

const usage = `usage: prolexic <command>

commands:
  version    print the version
`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version", "--version":
		v := version.Current()
		fmt.Fprintf(stdout, "prolexic %s (%s, %s, %s/%s)\n", v.Version, v.Commit, v.Go, v.OS, v.Arch)
		return exitSuccess
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitSuccess
	default:
		fmt.Fprintf(stderr, "prolexic: unknown command %q\n%s", args[0], usage)
		return exitUsage
	}
}
