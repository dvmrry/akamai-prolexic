package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/output"
	"github.com/dvmrry/akamai-prolexic/internal/version"
)

// VersionDoc is the build's version.
type VersionDoc struct {
	output.Header
	version.Info
}

func (*VersionDoc) SchemaID() string { return "prolexic.version.v1" }

func (d *VersionDoc) WriteText(w io.Writer) error {
	_, err := fmt.Fprintf(w, "prolexic %s (%s, %s, %s/%s)\n", d.Version, d.Commit, d.Go, d.OS, d.Arch)
	return err
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(context.Context, []string) (output.Document, error) {
			return &VersionDoc{Info: version.Current()}, nil
		}),
	}
}
