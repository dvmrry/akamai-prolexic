package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

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

func (d *RoutedSessionsDoc) Outcome() error { return failuresOutcome(d.Failures, d.Customers) }

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

// RoutedSessionsInput lists BGP sessions.
type RoutedSessionsInput struct {
	Customers []string // customer names; empty means every in-use name
}

// RoutedSessions lists the BGP sessions of each customer name; a name whose
// query failed is reported in the document, not as an error.
func (r *Runtime) RoutedSessions(ctx context.Context, in RoutedSessionsInput) (*RoutedSessionsDoc, error) {
	api, err := r.analytics()
	if err != nil {
		return nil, err
	}
	res, err := analytics.ForCustomers(ctx, api, analytics.ResolveCustomers, in.Customers, api.BGPSessions)
	if res == nil {
		return nil, err
	}
	slices.SortStableFunc(res.Rows, func(x, y analytics.BGPSession) int {
		return cmp.Or(
			cmp.Compare(x.Customer, y.Customer),
			cmp.Compare(x.DataCenter, y.DataCenter),
			cmp.Compare(x.RouterName, y.RouterName),
			cmp.Compare(x.CustomerBgpPeerIpv4, y.CustomerBgpPeerIpv4),
			cmp.Compare(rowKey(x), rowKey(y)), // full tie-break: stable output whatever the API order
		)
	})
	return &RoutedSessionsDoc{Customers: res.Customers, Sessions: res.Rows, Failures: res.Failures}, nil
}
