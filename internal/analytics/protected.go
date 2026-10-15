package analytics

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Protected is what the plan's own-space check takes as ours for one customer
// name: the protected prefixes (MetricTypes) and the AS numbers of its BGP
// sessions.
type Protected struct {
	Customer string         `json:"customer" doc:"The customer name queried."`
	Site     string         `json:"site,omitempty" doc:"The metric types response's currentContract."`
	Prefixes []netip.Prefix `json:"prefixes" doc:"Flow Based Monitoring subnets, masked, sorted."`
	ASNs     []int64        `json:"asns" doc:"Own AS numbers from the BGP sessions, sorted."`
	Notes    []string       `json:"notes" doc:"What an empty list means."`
	// NoRouted is set when the name has no BGP sessions (a 404): its AS
	// numbers are unknown, not none.
	NoRouted bool `json:"noRouted,omitempty" doc:"No BGP sessions (404): AS numbers unknown."`
}

// ProtectedFor gathers one customer name's protected prefixes and own AS
// numbers. A 404 from the BGP sessions means the name has no Routed: no AS
// numbers, noted, not a failure. Any other error fails the name.
func (c *Client) ProtectedFor(ctx context.Context, customer string) (Protected, error) {
	out := Protected{Customer: customer, Prefixes: []netip.Prefix{}, ASNs: []int64{}, Notes: []string{}}
	m, err := c.MetricTypes(ctx, customer)
	if err != nil {
		return out, err
	}
	out.Site = m.Site
	out.Prefixes = m.Prefixes
	if len(m.Prefixes) == 0 {
		out.Notes = append(out.Notes, "no protected prefixes reported (unknown, not nothing protected)")
	}
	if m.Unparsable > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("%d subnet entries were not prefixes and are left out", m.Unparsable))
	}
	sessions, err := c.BGPSessions(ctx, customer)
	if err != nil {
		if !isNotFound(err) {
			return out, err
		}
		out.Notes = append(out.Notes, "no Routed: no BGP sessions (404), so no AS numbers")
		out.NoRouted = true
		return out, nil
	}
	for _, s := range sessions {
		if s.ASN > 0 && s.ASN <= math.MaxUint32 && !slices.Contains(out.ASNs, s.ASN) {
			out.ASNs = append(out.ASNs, s.ASN)
		}
	}
	slices.Sort(out.ASNs)
	if len(out.ASNs) == 0 {
		out.Notes = append(out.Notes, "BGP sessions carry no AS number")
	}
	return out, nil
}

// AllCustomers returns the explicit names (deduplicated), or every name of
// the account, in use or not, sorted. An inactive name's space is still ours.
func AllCustomers(ctx context.Context, c *Client, explicit []string) ([]string, error) {
	if len(explicit) > 0 {
		return ResolveCustomers(ctx, c, explicit)
	}
	all, err := c.CustomerNames(ctx)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeOf(err), err, "resolve customer names")
	}
	var out []string
	for _, n := range all {
		if n.Name != "" && !slices.Contains(out, n.Name) {
			out = append(out, n.Name)
		}
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil, apperr.New(apperr.NotFound, "the account has no customer names")
	}
	return out, nil
}
