package cli

import (
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

const routesFixture = `[
  {"akamaiLocation":"LOC-B","dataCenter":"DC-B","routerName":"edge-2","prefix":"203.0.113.0/24","customerBgpPeerIp":"192.0.2.6","asPath":"64500","customerName":"example-a","localPref":100},
  {"akamaiLocation":"LOC-A","dataCenter":"DC-A","routerName":"edge-1","prefix":"203.0.113.0/24","customerBgpPeerIp":"192.0.2.14","asPath":"64500","customerName":"example-a","med":5},
  {"akamaiLocation":"LOC-A","dataCenter":"DC-A","routerName":"edge-1","prefix":"198.51.100.0/24","customerBgpPeerIp":"192.0.2.14","asPath":"64500","customerName":"example-a"},
  {"akamaiLocation":"LOC-A","dataCenter":"DC-A","routerName":"edge-1","prefix":"2001:db8::1/128","customerBgpPeerIp":"2001:db8::2","asPath":"64500","customerName":"example-a"}
]`

func TestRoutedRoutesSortsAndFilters(t *testing.T) {
	api := newFakeAPI(t)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/routes", 200, routesFixture)

	r := runCLI(t, api.env(), "routed", "routes", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.RoutedRoutesDoc](t, r.stdout, "prolexic.routed-routes.v1")
	if len(doc.Routes) != 4 {
		t.Fatalf("routes = %+v", doc.Routes)
	}
	var got []string
	for _, rt := range doc.Routes {
		got = append(got, rt.Prefix+"@"+rt.DataCenter)
	}
	want := "198.51.100.0/24@DC-A 2001:db8::1/128@DC-A 203.0.113.0/24@DC-A 203.0.113.0/24@DC-B"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
	if doc.Routes[0].Customer != "example-a" {
		t.Errorf("customer not set: %+v", doc.Routes[0])
	}

	// Exact, masked match; a covering or covered prefix is not a match.
	for _, tt := range []struct {
		prefix string
		want   int
	}{
		{"203.0.113.9/24", 2},
		{"203.0.113.0/25", 0},
		{"2001:db8::1", 1},
	} {
		r := runCLI(t, api.env(), "routed", "routes", "--customer", "example-a", "--prefix", tt.prefix)
		doc := decode[ops.RoutedRoutesDoc](t, r.stdout, "prolexic.routed-routes.v1")
		if len(doc.Routes) != tt.want {
			t.Errorf("--prefix %s: %d routes, want %d", tt.prefix, len(doc.Routes), tt.want)
		}
	}
}

func TestRoutedRoutesBadPrefix(t *testing.T) {
	r := runCLI(t, newFakeAPI(t).env(), "routed", "routes", "--prefix", "nope")
	if r.code != exitCode(apperr.Usage) {
		t.Errorf("exit = %d, want 2", r.code)
	}
}

func TestRoutedRoutesReportsFailedNames(t *testing.T) {
	api := newFakeAPI(t)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/routes", 403, `{"errorCode":"FORBIDDEN","message":"no access"}`)
	r := runCLI(t, api.env(), "routed", "routes", "--customer", "example-bad", "--format", "text")
	if r.code != exitCode(apperr.Credentials) || !strings.Contains(r.stdout, "failed: example-bad") {
		t.Errorf("exit %d, stdout:\n%s", r.code, r.stdout)
	}
}
