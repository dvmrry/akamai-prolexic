package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func newEventsCmd(a *app) *cobra.Command {
	var in ops.EventsInput
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "events",
		Short: "critical events and events per customer name",
		Long:  "Critical events and events per customer name. The API has no time window for events: --since, --start and --end filter the answer, keeping events whose span overlaps the window. With none of them, every event is listed.",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			var err error
			if in.Window, err = win.window(); err != nil {
				return nil, err
			}
			return docOf(a.ops().Events(ctx, in))
		}),
	}
	customerFlag(cmd, &in.Customers)
	cmd.Flags().BoolVar(&in.CriticalOnly, "critical-only", false, "only critical events")
	win.register(cmd, 0)
	return cmd
}
