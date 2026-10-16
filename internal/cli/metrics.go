package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

const typeHelp = "SERVICE:METRIC, or fbm:METRIC:PROTOCOL (repeatable or comma-separated); e.g. routed:bandwidthIn, fbm:bandwidth:total"

func newMetricsCmd(a *app) *cobra.Command {
	var in ops.MetricsInput
	var win windowFlags
	cmd := &cobra.Command{
		Use:     "metrics",
		Short:   "traffic metrics per customer name",
		Example: "  prolexic metrics --type routed:bandwidthIn --since 6h",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			var err error
			if in.Window, err = win.window(); err != nil {
				return nil, err
			}
			return output.Doc(a.ops().Metrics(ctx, in))
		}),
	}
	f := cmd.Flags()
	listVar(f, &in.Customers, "customer", "customer name (the API's contract) to query; repeatable or comma-separated (default: every in-use name)")
	listVar(f, &in.Types, "type", typeHelp)
	f.StringVar(&in.Subnet, "subnet", "", "the subnet fbm types report on (fbm types need --subnet or --ip)")
	f.StringVar(&in.IP, "ip", "", "the IP address fbm types report on (fbm types need --subnet or --ip)")
	f.IntVar(&in.Samples, "samples", ops.MetricsDefaultSamples, "number of data points to return")
	win.register(cmd, ops.MetricsDefaultSince)
	return cmd
}
