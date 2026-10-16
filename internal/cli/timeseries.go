package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newTimeSeriesCmd(a *app) *cobra.Command {
	var in ops.TimeSeriesInput
	var win windowFlags
	cmd := &cobra.Command{
		Use:     "time-series",
		Short:   "flow usage and attack traffic per destination",
		Example: "  prolexic time-series --destination 198.51.100.0/24 --location agr --since 2h",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			var err error
			if in.Window, err = win.window(); err != nil {
				return nil, err
			}
			return output.Doc(a.ops().TimeSeries(ctx, in))
		}),
	}
	f := cmd.Flags()
	listVar(f, &in.Destinations, "destination", "address or CIDR block (required); repeatable or comma-separated")
	listVar(f, &in.Locations, "location", "data center such as mia4, or agr for all aggregated; repeatable or comma-separated (default: agr)")
	f.StringVar(&in.Source, "source", ops.TimeSeriesDefaultSource, "router type: both, access_flow (Akamai router) or border_flow (customer router)")
	f.BoolVar(&in.Sum, "sum", false, "also return the aggregatedData facet")
	f.IntVar(&in.Samples, "samples", 0, "number of timestamps to return (default: all in the window)")
	win.register(cmd, ops.TimeSeriesDefaultSince)
	_ = cmd.MarkFlagRequired("destination")
	return cmd
}
