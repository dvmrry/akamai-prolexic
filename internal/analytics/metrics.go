package analytics

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Number is a JSON number that also reads a numeric string. Anything else
// (null, objects, unknown strings) decodes to 0 without an error.
type Number float64

func (n *Number) UnmarshalJSON(b []byte) error {
	*n = 0
	s := strings.Trim(string(bytes.TrimSpace(b)), `"`)
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		*n = Number(f) // NaN and Inf would break JSON encoding: left at 0
	}
	return nil
}

// JSONSchema describes the encoded form: a number.
func (Number) JSONSchema() map[string]any { return map[string]any{"type": "number"} }

func isNotFound(err error) bool {
	u := apperr.UpstreamOf(err)
	return u != nil && u.Status == http.StatusNotFound
}

// MetricsMaxSpan is the longest window POST /metrics accepts.
const MetricsMaxSpan = 90 * 24 * time.Hour

// MetricQuery selects what POST /metrics returns for one customer name.
// Services maps a service (connect, mitigationPost, mitigationPre, proxy,
// routed) to metric names; FBM entries are objects and go in FBM.
type MetricQuery struct {
	Services map[string][]string
	FBM      []FBMMetric
	Start    time.Time
	End      time.Time
	Samples  int
}

// FBMMetric is one Flow Based Monitoring metric. Subnet and IP are exclusive.
type FBMMetric struct {
	Metric   string `json:"metric"`
	Protocol string `json:"protocol"`
	Subnet   string `json:"subnet,omitempty"`
	IP       string `json:"ip,omitempty"`
}

// MetricSeries is one series of a metrics response.
type MetricSeries struct {
	Customer string     `json:"customer" doc:"The customer name queried; added by prolexic."`
	Site     string     `json:"site,omitempty" doc:"The response's currentContract."`
	Service  string     `json:"service,omitempty"`
	Metric   string     `json:"metric"`
	Protocol string     `json:"protocol,omitempty"`
	Subnet   string     `json:"subnet,omitempty"`
	IP       string     `json:"ip,omitempty"`
	Points   [][]Number `json:"points" doc:"[timestamp, value] pairs, as the API sends them (timestamps are not normalised)."`
}

// Metrics runs the metrics query for one customer name. The POST only reads,
// so it is marked ReadOnly. A 404 means the window holds no data: zero rows.
func (c *Client) Metrics(ctx context.Context, customer string, q MetricQuery) ([]MetricSeries, error) {
	types := map[string]any{}
	for svc, ms := range q.Services {
		types[svc] = ms
	}
	if len(q.FBM) > 0 {
		types["fbm"] = q.FBM
	}
	body := map[string]any{
		"contract": customer,
		"start":    q.Start.Unix(),
		"end":      q.End.Unix(),
		"samples":  q.Samples,
		"type":     types,
	}
	var resp struct {
		envelope
		Data []MetricSeries `json:"data"`
	}
	err := c.c.Do(ctx, akamai.Request{Method: http.MethodPost, Path: basePath + "/metrics", JSON: body, ReadOnly: true}, &resp)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := resp.err("metrics"); err != nil {
		return nil, err
	}
	for i := range resp.Data {
		resp.Data[i].Customer = customer
		resp.Data[i].Site = resp.CurrentContract
		if resp.Data[i].Points == nil {
			resp.Data[i].Points = [][]Number{}
		}
	}
	return resp.Data, nil
}
