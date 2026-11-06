package analytics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
)

func testAPI(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(akamai.New(edgegrid.Credentials{
		Host: strings.TrimPrefix(srv.URL, "http://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at",
	}, akamai.Options{Scheme: "http"}))
}

const metricTypesFixture = `{"currentContract":"site-a","status":true,"statusMsg":"ok","data":{
  "fbm":{"metrics":{
    "bandwidth":{"desc":"d","protocols":["total"],"subnets":["203.0.113.0/24","198.51.100.77/25","192.0.2.9","not-a-prefix","2001:db8::/32"]},
    "packets":{"desc":"d","protocols":["total"],"subnets":["203.0.113.0/24","2001:db8:0::/32","","203.0.113.0/99"]}}},
  "routed":{"metrics":{"bandwidthIn":{"desc":"x"}}},
  "somethingNew":{}}}`

func TestMetricTypes(t *testing.T) {
	var gotPath string
	c := testAPI(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Write([]byte(metricTypesFixture))
	})
	mt, err := c.MetricTypes(context.Background(), "example a")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/prolexic-analytics/v2/metric-types/example%20a" {
		t.Errorf("path = %q", gotPath)
	}
	var got []string
	for _, p := range mt.Prefixes {
		got = append(got, p.String())
	}
	want := "192.0.2.9/32 198.51.100.0/25 203.0.113.0/24 2001:db8::/32"
	if strings.Join(got, " ") != want {
		t.Errorf("prefixes = %v, want %s (masked, deduplicated, sorted)", got, want)
	}
	if mt.Site != "site-a" || mt.Customer != "example a" || mt.Unparsable != 3 {
		t.Errorf("site=%q customer=%q unparsable=%d, want site-a, example a, 3", mt.Site, mt.Customer, mt.Unparsable)
	}
	for p, want := range map[string]bool{
		"203.0.113.64/26": true, "203.0.113.0/24": true, "203.0.113.0/23": false,
		"198.51.100.200/32": false, "2001:db8:1::/48": true, "192.0.2.9/32": true, "192.0.2.8/32": false,
	} {
		if got := mt.Contains(netip.MustParsePrefix(p)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", p, got, want)
		}
	}
}

func TestMetricTypesWithoutFBMHasNoPrefixes(t *testing.T) {
	c := testAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"currentContract":"site-a","status":true,"data":{"routed":{}}}`))
	})
	mt, err := c.MetricTypes(context.Background(), "example-a")
	if err != nil || mt.Prefixes == nil || len(mt.Prefixes) != 0 {
		t.Errorf("mt = %+v, err = %v", mt, err)
	}
}

func TestMetricTypesErrors(t *testing.T) {
	c := testAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":false,"statusMsg":"no such customer"}`))
	})
	if _, err := c.MetricTypes(context.Background(), "example-a"); apperr.KindOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "no such customer") {
		t.Errorf("status=false: err = %v", err)
	}
	if _, err := c.MetricTypes(context.Background(), "a/b"); apperr.KindOf(err) != apperr.Usage {
		t.Errorf("slash in name: err = %v", err)
	}
	c = testAPI(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) })
	if _, err := c.MetricTypes(context.Background(), "example-a"); apperr.KindOf(err) != apperr.NotFound {
		t.Errorf("404: err = %v", err)
	}
}
