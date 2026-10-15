// Package networkhealth is a read-only client for Prolexic Network Health v1.
//
// Targets are per account: the API takes no contract or customer name, and
// GET /targets returns every target in one response (the spec has no paging).
// Wire types mirror the spec's field names and decode leniently; they double
// as output rows. Only GETs are made.
package networkhealth

import (
	"context"
	"net/http"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

const basePath = "/prolexic-network-health/v1"

// Client calls Prolexic Network Health v1.
type Client struct {
	c *akamai.Client
}

// New wraps a transport client.
func New(c *akamai.Client) *Client { return &Client{c: c} }

// Target is a monitored network target.
type Target struct {
	TargetID     string `json:"targetId"`
	TargetName   string `json:"targetName"`
	AccountID    string `json:"accountId,omitempty"`
	TestType     string `json:"testType" doc:"TCP or HTTP."`
	TargetIP     string `json:"targetIp,omitempty" doc:"A single address for TCP tests; null (shown absent) for HTTP."`
	TargetDomain string `json:"targetDomain,omitempty" doc:"The domain for HTTP tests; null or empty (shown absent) for TCP."`
	Ports        []int  `json:"ports" doc:"The TCP ports monitored."`
	TestIDs      []int  `json:"testIds" doc:"The test ids the target uses."`
	CreatedBy    string `json:"createdBy,omitempty"`
	CreatedTime  string `json:"createdTime,omitempty" doc:"ISO 8601, as the API reports it."`
	ModifiedBy   string `json:"modifiedBy,omitempty"`
	ModifiedTime string `json:"modifiedTime,omitempty" doc:"ISO 8601, as the API reports it."`
}

func (t *Target) normalise() {
	if t.Ports == nil {
		t.Ports = []int{}
	}
	if t.TestIDs == nil {
		t.TestIDs = []int{}
	}
}

// Targets lists every target of the account.
func (c *Client) Targets(ctx context.Context) ([]Target, error) {
	var resp struct {
		Targets []Target `json:"targets"`
	}
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: basePath + "/targets"}, &resp); err != nil {
		return nil, err
	}
	for i := range resp.Targets {
		resp.Targets[i].normalise()
	}
	return resp.Targets, nil
}

// Target returns one target; an unknown id is a 404 (exit 4).
func (c *Client) Target(ctx context.Context, id string) (*Target, error) {
	seg, err := akamai.PathSegment("target id", id)
	if err != nil {
		return nil, err
	}
	var t Target
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: basePath + "/targets/" + seg}, &t); err != nil {
		return nil, err
	}
	t.normalise()
	return &t, nil
}
