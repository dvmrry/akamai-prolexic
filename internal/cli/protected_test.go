package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

const protectedNames = `{"customerNames":[
  {"name":"example-old","contractId":"C-EXAMPLE","accountName":"Example","inUse":false},
  {"name":"example-a","contractId":"C-EXAMPLE","accountName":"Example","inUse":true},
  {"name":"example-bad","contractId":"C-EXAMPLE","accountName":"Example","inUse":true}]}`

func protectedAPI(t *testing.T) *fakeAPI {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/customer/names", 200, protectedNames)
	api.json("GET /prolexic-analytics/v2/metric-types/example-a", 200, `{"currentContract":"site-a","status":true,"data":{"fbm":{"metrics":{
	  "bandwidth":{"subnets":["203.0.113.0/24","198.51.100.0/25"]},"packets":{"subnets":["203.0.113.0/24"]}}}}}`)
	api.json("GET /prolexic-analytics/v2/metric-types/example-old", 200, `{"currentContract":"site-old","status":true,"data":{}}`)
	api.json("GET /prolexic-analytics/v2/metric-types/example-bad", 403, `{"errorCode":"FORBIDDEN","message":"no access"}`)
	api.routes["POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions"] = func(w http.ResponseWriter, r *http.Request) {
		var b struct{ CustomerNames []string }
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(b.CustomerNames) == 1 && b.CustomerNames[0] == "example-a" {
			w.Write([]byte(`[{"dataCenter":"DC-B","asn":64501},{"dataCenter":"DC-A","asn":64500},{"dataCenter":"DC-C","asn":64500}]`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte(`{"errorCode":"NOT_FOUND","message":"no routed"}`))
	}
	return api
}

func TestProtectedAllNamesNoRoutedIsNotAFailure(t *testing.T) {
	api := protectedAPI(t)
	r := runCLI(t, api.env(), "protected")
	doc := decode[ops.ProtectedDoc](t, r.stdout, "prolexic.protected.v1")
	// example-bad's metric types fail: reported, exit 3, the others still shown.
	if r.code != exitCode(apperr.Credentials) || len(doc.Failures) != 1 || doc.Failures[0].Customer != "example-bad" {
		t.Fatalf("exit %d, failures %+v", r.code, doc.Failures)
	}
	if strings.Join(doc.Customers, ",") != "example-a,example-bad,example-old" || len(doc.Protected) != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	a, old := doc.Protected[0], doc.Protected[1]
	if a.Customer != "example-a" || a.Site != "site-a" || len(a.Prefixes) != 2 || a.Prefixes[0].String() != "198.51.100.0/25" ||
		len(a.ASNs) != 2 || a.ASNs[0] != 64500 || a.ASNs[1] != 64501 || len(a.Notes) != 0 {
		t.Errorf("example-a = %+v", a)
	}
	// An inactive name is included; no prefixes is "unknown", a 404 is "no Routed".
	if old.Customer != "example-old" || len(old.Prefixes) != 0 || len(old.ASNs) != 0 || len(old.Notes) != 2 ||
		!strings.Contains(old.Notes[1], "no Routed") {
		t.Errorf("example-old = %+v", old)
	}

	r = runCLI(t, api.env(), "protected", "--customer", "example-old", "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "no Routed") || strings.Contains(r.stdout, "failed:") {
		t.Errorf("exit %d, text:\n%s", r.code, r.stdout)
	}
}

func TestProtectedBGPErrorOtherThan404Fails(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/metric-types/example-a", 200, `{"currentContract":"site-a","status":true,"data":{}}`)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 403, `{"errorCode":"FORBIDDEN","message":"no access"}`)
	r := runCLI(t, api.env(), "protected", "--customer", "example-a")
	doc := decode[ops.ProtectedDoc](t, r.stdout, "prolexic.protected.v1")
	if r.code != exitCode(apperr.Credentials) || len(doc.Failures) != 1 || len(doc.Protected) != 0 {
		t.Errorf("exit %d, doc %+v", r.code, doc)
	}
}

// A session without a usable AS number is counted and noted, not dropped unseen.
func TestProtectedCountsSessionsWithoutAnASN(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/metric-types/example-a", 200, `{"currentContract":"site-a","status":true,"data":{}}`)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 200, `[{"dataCenter":"DC-A","asn":64500},{"dataCenter":"DC-B"},{"dataCenter":"DC-C","asn":-1}]`)
	r := runCLI(t, api.env(), "protected", "--customer", "example-a")
	doc := decode[ops.ProtectedDoc](t, r.stdout, "prolexic.protected.v1")
	if r.code != 0 || len(doc.Protected) != 1 {
		t.Fatalf("exit %d, doc %+v", r.code, doc)
	}
	p := doc.Protected[0]
	if len(p.ASNs) != 1 || p.ASNs[0] != 64500 || p.UnusableASNs != 2 || !strings.Contains(strings.Join(p.Notes, "\n"), "2 BGP sessions have no usable AS number") {
		t.Errorf("protected = %+v", p)
	}
}
