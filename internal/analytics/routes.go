package analytics

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Route is one BGP route a customer router announces to Akamai.
type Route struct {
	Customer          string   `json:"customer" doc:"The customer name queried; added by prolexic."`
	AkamaiLocation    string   `json:"akamaiLocation"`
	DataCenter        string   `json:"dataCenter,omitempty"`
	RouterName        string   `json:"routerName"`
	TunnelType        string   `json:"tunnelType,omitempty"`
	Prefix            string   `json:"prefix" doc:"The announced prefix, as the API reports it."`
	CustomerBgpPeerIp string   `json:"customerBgpPeerIp" doc:"The BGP peer that announced the prefix; matches a session's customerBgpPeerIpv4 or customerBgpPeerIpv6."`
	ASPath            string   `json:"asPath"`
	Community         []string `json:"community,omitempty"`
	LocalPref         *int64   `json:"localPref,omitempty"`
	MED               *int64   `json:"med,omitempty"`
	MTU               int      `json:"mtu,omitempty"`
}

// Routes returns one customer name's announced routes, with Customer set.
func (c *Client) Routes(ctx context.Context, customer string) ([]Route, error) {
	var out []Route
	err := c.routedPost(ctx, "/routed/tunnel/routes", customer, &out)
	for i := range out {
		out[i].Customer = customer
	}
	return out, err
}

// TunnelHealth is the tunnel count for one Akamai location and customer
// router. Counts are per Akamai endpoint IP and remote endpoint IP.
type TunnelHealth struct {
	Customer          string `json:"customer" doc:"The customer name queried; added by prolexic."`
	AkamaiLocation    string `json:"akamaiLocation"`
	RouterName        string `json:"routerName"`
	HealthyFunnels    int    `json:"healthyFunnels"`
	TotalFunnels      int    `json:"totalFunnels"`
	HealthyAdcFunnels int    `json:"healthyAdcFunnels,omitempty"`
	TotalAdcFunnels   int    `json:"totalAdcFunnels,omitempty"`
}

// Healthy reports whether every tunnel, ADC ones included, is healthy.
func (h TunnelHealth) Healthy() bool {
	return h.HealthyFunnels >= h.TotalFunnels && h.HealthyAdcFunnels >= h.TotalAdcFunnels
}

// TunnelHealth returns one customer name's tunnel health rows, with Customer set.
func (c *Client) TunnelHealth(ctx context.Context, customer string) ([]TunnelHealth, error) {
	var out []TunnelHealth
	err := c.routedPost(ctx, "/routed/tunnel/health", customer, &out)
	for i := range out {
		out[i].Customer = customer
	}
	return out, err
}

func (c *Client) routedPost(ctx context.Context, path, customer string, out any) error {
	return c.c.Do(ctx, akamai.Request{
		Method:   http.MethodPost,
		Path:     basePath + path,
		JSON:     customerNamesBody{CustomerNames: []string{customer}},
		ReadOnly: true,
	}, out)
}

// ParsePrefix parses a prefix and masks it. A bare address is a host route
// (/32 or /128). An IPv4-mapped IPv6 prefix is not unmapped.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, apperr.New(apperr.Usage, "invalid prefix %q: want CIDR or a bare address", s)
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, apperr.New(apperr.Usage, "invalid prefix %q: %v", s, err)
	}
	return p.Masked(), nil
}

// SamePrefix reports whether the API-reported prefix s equals p exactly (both
// masked). An unparsable s is never equal.
func SamePrefix(s string, p netip.Prefix) bool {
	q, err := ParsePrefix(s)
	return err == nil && q == p.Masked()
}
