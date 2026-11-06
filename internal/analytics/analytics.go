// Package analytics is a read-only client for Prolexic Analytics v2.
//
// The API takes a customer name, not a contract id, both in the {contract}
// path parameter and in the customerNames request field. One account can
// hold many names; commands resolve them once and fan out with FanOut.
//
// Wire types mirror the spec's field names, decode leniently (unknown fields
// are ignored, missing optional fields are zero) and double as output rows:
// a command adds the customer name and sorts, nothing more.
package analytics

import (
	"context"
	"net/http"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

const basePath = "/prolexic-analytics/v2"

// Client calls Prolexic Analytics v2.
type Client struct {
	c *akamai.Client
}

// New wraps a transport client.
func New(c *akamai.Client) *Client { return &Client{c: c} }

// CustomerName is one entry of GET /customer/names.
type CustomerName struct {
	Name        string `json:"name"`
	ContractID  string `json:"contractId"`
	AccountName string `json:"accountName"`
	InUse       bool   `json:"inUse"`
}

// CustomerNames lists the account's customer names.
func (c *Client) CustomerNames(ctx context.Context) ([]CustomerName, error) {
	var resp struct {
		CustomerNames []CustomerName `json:"customerNames"`
	}
	err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: basePath + "/customer/names"}, &resp)
	return resp.CustomerNames, err
}

// customerNamesBody is the request body of the routed endpoints. They are
// POSTs but read-only.
type customerNamesBody struct {
	CustomerNames []string `json:"customerNames"`
}

// BGPSession is one Routed 3.0 GRE or GRE-over-ADC tunnel's BGP session.
type BGPSession struct {
	Customer                string `json:"customer" doc:"The customer name queried; added by prolexic."`
	DataCenter              string `json:"dataCenter"`
	RouterName              string `json:"routerName"`
	TunnelType              string `json:"tunnelType,omitempty"`
	ASN                     int64  `json:"asn"`
	MTU                     int    `json:"mtu,omitempty"`
	AkamaiGreEndpointIpv4   string `json:"akamaiGreEndpointIpv4"`
	AkamaiGreEndpointIpv6   string `json:"akamaiGreEndpointIpv6,omitempty"`
	CustomerGreEndpointIpv4 string `json:"customerGreEndpointIpv4"`
	CustomerGreEndpointIpv6 string `json:"customerGreEndpointIpv6,omitempty"`
	AkamaiBgpPeerIpv4       string `json:"akamaiBgpPeerIpv4"`
	AkamaiBgpPeerIpv6       string `json:"akamaiBgpPeerIpv6,omitempty"`
	CustomerBgpPeerIpv4     string `json:"customerBgpPeerIpv4"`
	CustomerBgpPeerIpv6     string `json:"customerBgpPeerIpv6,omitempty"`
	HealthIpv4              string `json:"healthIpv4"`
	HealthIpv6              string `json:"healthIpv6,omitempty"`
}

// BGPSessions returns one customer name's BGP sessions, with Customer set.
func (c *Client) BGPSessions(ctx context.Context, customer string) ([]BGPSession, error) {
	var out []BGPSession
	err := c.c.Do(ctx, akamai.Request{
		Method:   http.MethodPost,
		Path:     basePath + "/routed/tunnel/bgp-sessions",
		JSON:     customerNamesBody{CustomerNames: []string{customer}},
		ReadOnly: true,
	}, &out)
	for i := range out {
		out[i].Customer = customer
	}
	return out, err
}
