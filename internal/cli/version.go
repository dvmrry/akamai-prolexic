package cli

import (
	"context"
	"fmt"
	"io"

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

func runVersion(_ context.Context, a *app, args []string) (output.Document, error) {
	if err := a.parse(a.flags(), args, false); err != nil {
		return nil, err
	}
	return &VersionDoc{Info: version.Current()}, nil
}
