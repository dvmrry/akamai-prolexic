package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// RoutedSessionsDoc lists BGP sessions across customer names.
type RoutedSessionsDoc struct {
	output.Header
	Customers []string               `json:"customers" doc:"The customer names queried."`
	Sessions  []analytics.BGPSession `json:"sessions" doc:"Sorted by customer, dataCenter, routerName, customerBgpPeerIpv4."`
	Failures  []analytics.Failure    `json:"failures" doc:"Customer names whose query failed."`
}

func (*RoutedSessionsDoc) SchemaID() string { return "prolexic.routed-sessions.v1" }

func (d *RoutedSessionsDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CUSTOMER\tDATA CENTER\tROUTER\tTUNNEL\tASN\tPEER V4\tPEER V6\tHEALTH V4\tHEALTH V6")
	for _, s := range d.Sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", s.Customer, s.DataCenter, s.RouterName,
			dash(s.TunnelType), s.ASN, dash(s.CustomerBgpPeerIpv4), dash(s.CustomerBgpPeerIpv6), dash(s.HealthIpv4), dash(s.HealthIpv6))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return writeFailures(w, d.Failures)
}

func newRoutedSessionsCmd(a *app) *cobra.Command {
	var customers []string
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "BGP sessions per customer name",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return routedSessions(ctx, a, customers)
		}),
	}
	customerFlag(cmd, &customers)
	return cmd
}

// customerFlag is the --customer flag every fan-out command takes.
func customerFlag(cmd *cobra.Command, customers *[]string) {
	listVar(cmd.Flags(), customers, "customer", "customer name to query; repeatable or comma-separated (default: every in-use name)")
}

func routedSessions(ctx context.Context, a *app, customers []string) (output.Document, error) {
	api, err := a.analytics()
	if err != nil {
		return nil, err
	}
	names, err := analytics.ResolveCustomers(ctx, api, customers)
	if err != nil {
		return nil, err
	}
	rows, failures, err := analytics.FanOut(ctx, names, api.BGPSessions)
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr // err may be nil if cancellation came after FanOut returned
	}
	slices.SortStableFunc(rows, func(x, y analytics.BGPSession) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.DataCenter, y.DataCenter),
			cmp.Compare(x.RouterName, y.RouterName),
			cmp.Compare(x.CustomerBgpPeerIpv4, y.CustomerBgpPeerIpv4),
			cmp.Compare(rowKey(x), rowKey(y)), // full tie-break: stable output whatever the API order
		)
	})
	return &RoutedSessionsDoc{Customers: names, Sessions: nonNil(rows), Failures: nonNil(failures)}, err
}

// analytics is the Prolexic Analytics client, over the read credentials.
func (a *app) analytics() (*analytics.Client, error) {
	c, err := a.readClient()
	if err != nil {
		return nil, err
	}
	return analytics.New(c), nil
}

// writeFailures appends a fan-out's failures to a text rendering.
func writeFailures(w io.Writer, failures []analytics.Failure) error {
	for _, f := range failures {
		if _, err := fmt.Fprintf(w, "\nfailed: %s: %s", f.Customer, f.Message); err != nil {
			return err
		}
	}
	if len(failures) > 0 {
		_, err := fmt.Fprintln(w)
		return err
	}
	return nil
}

// rowKey is a row's JSON encoding: the last sort key, so rows that tie on
// every named key still come out in one order whatever order the API sent.
func rowKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// nonNil keeps empty lists as [] rather than null in JSON: the schemas
// declare arrays.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
