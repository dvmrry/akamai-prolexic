package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const metricsFixture = `{"currentContract":"site-a","status":true,"statusMsg":"ok","data":[
  {"service":"routed","metric":"bandwidthIn","points":[[1767225600,10],["1767225660","12.5"]],"extra":1},
  {"service":"fbm","metric":"bandwidth","protocol":"total","subnet":"203.0.113.0/24","points":[[1767225600,5]]}
]}`

func TestMetricsQueryAndDecode(t *testing.T) {
	api := newFakeAPI(t)
	api.json("POST /prolexic-analytics/v2/metrics", 200, metricsFixture)
	env := api.env()
	env.Now = func() time.Time { return fixedNow }

	r := runCLI(t, env, "metrics", "--customer", "example-a", "--type", "routed:bandwidthIn,fbm:bandwidth:total", "--subnet", "203.0.113.0/24", "--samples", "50")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[MetricsDoc](t, r.stdout, "prolexic.metrics.v1")
	if len(doc.Series) != 2 || doc.Series[0].Service != "fbm" || doc.Series[0].Customer != "example-a" || doc.Series[0].Site != "site-a" {
		t.Fatalf("series = %+v", doc.Series)
	}
	if got := doc.Series[1].Points[1][1]; got != 12.5 {
		t.Errorf("string number = %v", got)
	}

	var body map[string]any
	for _, c := range api.calls {
		if c.Path == "/prolexic-analytics/v2/metrics" {
			if err := json.Unmarshal([]byte(c.Body), &body); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := `{"fbm":[{"metric":"bandwidth","protocol":"total","subnet":"203.0.113.0/24"}],"routed":["bandwidthIn"]}`
	got, _ := json.Marshal(body["type"])
	if string(got) != want || body["contract"] != "example-a" || body["samples"] != 50.0 ||
		body["end"] != float64(fixedNow.Unix()) || body["start"] != float64(fixedNow.Add(-24*time.Hour).Unix()) {
		t.Errorf("body = %v", body)
	}

	r = runCLI(t, env, "metrics", "--customer", "example-a", "--type", "routed:bandwidthIn", "--format", "text")
	if !strings.Contains(r.stdout, "12.5") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestMetricsEmptyWindowIs404AndFailuresReported(t *testing.T) {
	api := newFakeAPI(t)
	api.routes["POST /prolexic-analytics/v2/metrics"] = func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Contract string }
		json.NewDecoder(r.Body).Decode(&b)
		switch b.Contract {
		case "example-a":
			w.WriteHeader(404)
			w.Write([]byte(`{"errorCode":"NOT_FOUND","message":"no data"}`))
		case "example-c":
			w.WriteHeader(403)
			w.Write([]byte(`{"errorCode":"FORBIDDEN","message":"no access"}`))
		default:
			w.Write([]byte(metricsFixture))
		}
	}
	env := api.env()
	env.Now = func() time.Time { return fixedNow }
	r := runCLI(t, env, "metrics", "--customer", "example-a,example-b", "--type", "routed:bandwidthIn")
	doc := decode[MetricsDoc](t, r.stdout, "prolexic.metrics.v1")
	if r.code != 0 || len(doc.Series) != 2 {
		t.Errorf("exit %d, series %d", r.code, len(doc.Series))
	}
	r = runCLI(t, env, "metrics", "--customer", "example-a,example-c", "--type", "routed:bandwidthIn")
	if r.code != exitCode(apperr.Credentials) {
		t.Errorf("exit = %d, want 3", r.code)
	}
}

func TestMetricsFlagErrors(t *testing.T) {
	env := newFakeAPI(t).env()
	for _, args := range [][]string{
		{"metrics"},
		{"metrics", "--type", "nope:x"},
		{"metrics", "--type", "routed:latency"},
		{"metrics", "--type", "fbm:bandwidth"},
		{"metrics", "--type", "routed:bandwidthIn", "--subnet", "203.0.113.0/24"},
		{"metrics", "--type", "fbm:bandwidth:total", "--subnet", "203.0.113.0/24", "--ip", "203.0.113.1"},
		{"metrics", "--type", "routed:bandwidthIn", "--since", "2400h"},
		{"metrics", "--type", "routed:bandwidthIn", "--samples", "0"},
	} {
		if r := runCLI(t, env, args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
	}
}

func TestMetricsFBMNeedsSubnetOrIPBeforeAnyRequest(t *testing.T) {
	api := newFakeAPI(t)
	r := runCLI(t, api.env(), "metrics", "--customer", "example-a", "--type", "fbm:bandwidth:total")
	if r.code != exitCode(apperr.Usage) || !strings.Contains(r.stderr, "fbm types need --subnet or --ip") || len(api.calls) != 0 {
		t.Errorf("exit = %d, calls = %d, stderr = %s", r.code, len(api.calls), r.stderr)
	}
}
