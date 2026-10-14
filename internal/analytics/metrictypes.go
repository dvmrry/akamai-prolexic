package analytics

import (
	"context"
	"net/http"
	"net/netip"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

// MetricTypes is what GET /metric-types/{contract} says about one customer
// name, reduced to the part with a consumer: the prefixes Prolexic protects.
//
// Where the prefixes come from. The spec has no field called protected
// prefixes. The only prefix lists are the Flow Based Monitoring subnets
// ("the subnets available to your contract") under data.fbm.metrics.bandwidth
// and data.fbm.metrics.packets; MetricTypes.Prefixes is their union. A
// customer name without FBM data has none, which does not mean nothing is
// protected: callers that validate "is this prefix mine" must treat an empty
// list as unknown, not as "no".
//
// Site. The response names one site: currentContract, "the policy name of the
// data center or proxy". So a MetricTypes is one site's view, and Site is
// that name (empty if the API omitted it). Callers wanting several sites
// query several customer names.
type MetricTypes struct {
	Customer string `json:"customer" doc:"The customer name queried; added by prolexic."`
	Site     string `json:"site,omitempty" doc:"The response's currentContract."`
	// Prefixes are masked (host bits cleared), a bare address is a /32 or
	// /128, deduplicated and sorted by address then length.
	Prefixes []netip.Prefix `json:"prefixes"`
	// Unparsable counts subnet entries that were not a prefix or address and
	// were left out of Prefixes.
	Unparsable int `json:"unparsable,omitempty"`
}

// Contains reports whether p lies within one of the protected prefixes.
func (m MetricTypes) Contains(p netip.Prefix) bool {
	p = p.Masked()
	for _, q := range m.Prefixes {
		if q.Addr().Is4() == p.Addr().Is4() && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// MetricTypes fetches one customer name's metric types.
func (c *Client) MetricTypes(ctx context.Context, customer string) (MetricTypes, error) {
	out := MetricTypes{Customer: customer, Prefixes: []netip.Prefix{}}
	path, err := contractPath("/metric-types/", customer, "")
	if err != nil {
		return out, err
	}
	type subnets struct {
		Subnets []string `json:"subnets"`
	}
	var resp struct {
		envelope
		Data struct {
			FBM struct {
				Metrics struct {
					Bandwidth subnets `json:"bandwidth"`
					Packets   subnets `json:"packets"`
				} `json:"metrics"`
			} `json:"fbm"`
		} `json:"data"`
	}
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: path}, &resp); err != nil {
		return out, err
	}
	if err := resp.err("metric types"); err != nil {
		return out, err
	}
	out.Site = resp.CurrentContract
	for _, list := range [][]string{resp.Data.FBM.Metrics.Bandwidth.Subnets, resp.Data.FBM.Metrics.Packets.Subnets} {
		for _, s := range list {
			p, err := ParsePrefix(s)
			if err != nil {
				out.Unparsable++
				continue
			}
			out.Prefixes = append(out.Prefixes, p)
		}
	}
	slices.SortFunc(out.Prefixes, func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return x.Bits() - y.Bits()
	})
	out.Prefixes = slices.Compact(out.Prefixes)
	return out, nil
}
