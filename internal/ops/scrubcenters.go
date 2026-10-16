package ops

import (
	"context"
	"fmt"
	"io"

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

// ScrubCenters lists the active scrub centers.
func (r *Runtime) ScrubCenters(ctx context.Context) (*ScrubCentersDoc, error) {
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	centers, err := api.ScrubCenters(ctx)
	if err != nil {
		return nil, err
	}
	return &ScrubCentersDoc{ScrubCenters: nonNil(centers)}, nil
}
