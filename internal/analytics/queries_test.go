package analytics

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Hour)
)

func TestParseMetricQuery(t *testing.T) {
	q, err := ParseMetricQuery([]string{"routed:packetsIn", "routed:bandwidthIn", "routed:packetsIn", "fbm:packets:udp", "fbm:bandwidth:total"},
		"203.0.113.0/24", "", t0, t1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"routed": {"bandwidthIn", "packetsIn"}}; !reflect.DeepEqual(q.Services(), want) {
		t.Errorf("services = %v", q.Services())
	}
	fbm := q.FBM()
	if len(fbm) != 2 || fbm[0].Metric != "bandwidth" || fbm[1].Protocol != "udp" || fbm[0].Subnet != "203.0.113.0/24" {
		t.Errorf("fbm = %+v", fbm)
	}
	if !q.Start().Equal(t0) || !q.End().Equal(t1) || q.Samples() != 50 {
		t.Errorf("window/samples = %v %v %d", q.Start(), q.End(), q.Samples())
	}

	ok := []string{"routed:bandwidthIn"}
	fbmT := []string{"fbm:bandwidth:total"}
	for name, tt := range map[string]struct {
		types      []string
		subnet, ip string
		start, end time.Time
		samples    int
		want       string
	}{
		"none":            {nil, "", "", t0, t1, 1, "no metric types"},
		"unknown service": {[]string{"nope:x"}, "", "", t0, t1, 1, `metric type "nope:x"`},
		"wrong metric":    {[]string{"routed:latency"}, "", "", t0, t1, 1, `metric type "routed:latency"`},
		"no colon":        {[]string{"routed"}, "", "", t0, t1, 1, `metric type "routed"`},
		"fbm short":       {[]string{"fbm:bandwidth"}, "", "", t0, t1, 1, `metric type "fbm:bandwidth"`},
		"fbm protocol":    {[]string{"fbm:bandwidth:sctp"}, "192.0.2.1", "", t0, t1, 1, `metric type "fbm:bandwidth:sctp"`},
		"fbm no target":   {fbmT, "", "", t0, t1, 1, "need a subnet or an ip"},
		"target no fbm":   {ok, "203.0.113.0/24", "", t0, t1, 1, "fbm types only"},
		"both targets":    {fbmT, "203.0.113.0/24", "203.0.113.1", t0, t1, 1, "exclusive"},
		"samples zero":    {ok, "", "", t0, t1, 0, "samples 0"},
		"reversed":        {ok, "", "", t1, t0, 1, "not before its end"},
		"empty window":    {ok, "", "", t0, t0, 1, "not before its end"},
		"too long":        {ok, "", "", t0, t0.Add(MetricsMaxSpan + time.Second), 1, "maximum of 90 days"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseMetricQuery(tt.types, tt.subnet, tt.ip, tt.start, tt.end, tt.samples)
			if apperr.KindOf(err) != apperr.Usage || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a usage error containing %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "--") {
				t.Errorf("SDK error names a flag: %v", err)
			}
		})
	}
	if _, err := ParseMetricQuery(ok, "", "", t0, t0.Add(MetricsMaxSpan), 1); err != nil {
		t.Errorf("a window of exactly the maximum span: %v", err)
	}
}

func TestParseTimeSeriesQuery(t *testing.T) {
	q, err := ParseTimeSeriesQuery([]string{"203.0.113.0/24", "198.51.100.7"}, nil, "both", true, 0, t0, t1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(q.Locations(), []string{"agr"}) || q.Source() != "both" || !q.Sum() || q.Samples() != 0 ||
		len(q.Destinations()) != 2 || !q.Start().Equal(t0) || !q.End().Equal(t1) {
		t.Errorf("query = %+v", q)
	}
	d := []string{"203.0.113.1"}
	for name, tt := range map[string]struct {
		dests, locs []string
		source      string
		samples     int
		start, end  time.Time
		want        string
	}{
		"no destination":  {nil, nil, "both", 0, t0, t1, "no destinations"},
		"bad destination": {[]string{"nope"}, nil, "both", 0, t0, t1, `destination "nope"`},
		"bad location":    {d, []string{"Miami"}, "both", 0, t0, t1, `location "Miami"`},
		"bad source":      {d, nil, "x", 0, t0, t1, `source "x"`},
		"empty source":    {d, nil, "", 0, t0, t1, `source ""`},
		"negative":        {d, nil, "both", -1, t0, t1, "samples -1"},
		"reversed":        {d, nil, "both", 0, t1, t0, "not before its end"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTimeSeriesQuery(tt.dests, tt.locs, tt.source, false, tt.samples, tt.start, tt.end)
			if apperr.KindOf(err) != apperr.Usage || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a usage error containing %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "--") {
				t.Errorf("SDK error names a flag: %v", err)
			}
		})
	}
	for _, l := range []string{"mia4", "agr", "lga3"} {
		if _, err := ParseTimeSeriesQuery(d, []string{l}, "border_flow", false, 3, t0, t1); err != nil {
			t.Errorf("location %q: %v", l, err)
		}
	}
}

// The client methods refuse a query that didn't come from its Parse function,
// before sending anything.
func TestQueriesRefuseZeroValue(t *testing.T) {
	c := &Client{} // no transport: a refusal must come before any request
	if _, err := c.Metrics(context.Background(), "example-a", MetricQuery{}); apperr.KindOf(err) != apperr.Bug {
		t.Errorf("Metrics err = %v, want a bug error", err)
	}
	if _, err := c.TimeSeries(context.Background(), TimeSeriesQuery{}); apperr.KindOf(err) != apperr.Bug {
		t.Errorf("TimeSeries err = %v, want a bug error", err)
	}
}
