package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ScrubCentersDoc lists the active scrub centers.
type ScrubCentersDoc struct {
	output.Header
	ScrubCenters []string `json:"scrubCenters" doc:"Active scrub center names, sorted."`
}

func (*ScrubCentersDoc) SchemaID() string { return "prolexic.scrub-centers.v1" }

func (d *ScrubCentersDoc) WriteText(w io.Writer) error {
	for _, s := range d.ScrubCenters {
		if _, err := fmt.Fprintln(w, s); err != nil {
			return err
		}
	}
	return nil
}

func newScrubCentersCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "scrub-centers",
		Short: "active scrub centers (read-only)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return scrubCenters(ctx, a)
		}),
	}
}

func scrubCenters(ctx context.Context, a *app) (output.Document, error) {
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	centers, err := api.ScrubCenters(ctx)
	if err != nil {
		return nil, err
	}
	return &ScrubCentersDoc{ScrubCenters: nonNil(centers)}, nil
}
