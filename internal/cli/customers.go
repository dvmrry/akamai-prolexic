package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// CustomersDoc lists the account's customer names.
type CustomersDoc struct {
	output.Header
	Customers []analytics.CustomerName `json:"customers" doc:"Sorted by name, contractId."`
}

func (*CustomersDoc) SchemaID() string { return "prolexic.customers.v1" }

func (d *CustomersDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCONTRACT\tACCOUNT\tIN USE")
	for _, c := range d.Customers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%t\n", c.Name, dash(c.ContractID), dash(c.AccountName), c.InUse)
	}
	return tw.Flush()
}

func newCustomersCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "customers",
		Short: "the account's customer names (read-only)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return customers(ctx, a)
		}),
	}
}

func customers(ctx context.Context, a *app) (output.Document, error) {
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	rows, err := api.CustomerNames(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y analytics.CustomerName) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.ContractID, y.ContractID))
	})
	return &CustomersDoc{Customers: nonNil(rows)}, nil
}
