package cli

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

const timeSeriesFixture = `{
  "203.0.113.0/24": {
    "inbound": {"1767225720": 3, "1767225660000": 2.5, "1767225600": "1"},
    "aggregatedData": {"total": 6.5}
  },
  "198.51.100.7": {"inbound": {"1767225600": 9}},
  "garbage": "x"
}`

func TestTimeSeriesQueryAndFlatten(t *testing.T) {
	api := newFakeAPI(t)
	var q url.Values
	api.routes["GET /prolexic-analytics/v2/time-series-data"] = func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		w.Write([]byte(timeSeriesFixture))
	}
	env := api.env()
	env.Now = func() time.Time { return fixedNow }

	r := runCLI(t, env, "time-series", "--destination", "203.0.113.0/24,198.51.100.7", "--location", "mia4,lga3", "--sum", "--samples", "3", "--source", "access_flow")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	want := map[string]string{
		"destinations": "203.0.113.0/24,198.51.100.7", "locations": "mia4,lga3", "source": "access_flow", "sum": "true",
		"samplingSize": "3", "startTime": "1767304800", "endTime": "1767312000",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), v)
		}
	}
	doc := decode[ops.TimeSeriesDoc](t, r.stdout, "prolexic.time-series.v1")
	if len(doc.Points) != 5 {
		t.Fatalf("points = %+v", doc.Points)
	}
	// Sorted by destination, facet, time; the millisecond key is normalised.
	p := doc.Points
	if p[0].Destination != "198.51.100.7" || p[1].Destination != "203.0.113.0/24" || p[1].Facet != "aggregatedData" || p[1].Time != 0 {
		t.Errorf("order = %+v", p)
	}
	if p[2].Time != 1767225600 || p[2].Value != 1 || p[3].Time != 1767225660 || p[3].Key != "1767225660000" || p[4].Time != 1767225720 {
		t.Errorf("inbound = %+v", p[2:5])
	}
}

func TestTimeSeriesNoDataIs404(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/time-series-data", 404, `{"errorCode":"NOT_FOUND","message":"none"}`)
	r := runCLI(t, api.env(), "time-series", "--destination", "203.0.113.1")
	doc := decode[ops.TimeSeriesDoc](t, r.stdout, "prolexic.time-series.v1")
	if r.code != 0 || len(doc.Points) != 0 || doc.Locations[0] != "agr" || doc.Source != "both" {
		t.Errorf("exit %d, doc %+v", r.code, doc)
	}
}

func TestTimeSeriesFlagErrors(t *testing.T) {
	env := newFakeAPI(t).env()
	for _, args := range [][]string{
		{"time-series"},
		{"time-series", "--destination", "nope"},
		{"time-series", "--destination", "203.0.113.1", "--location", "Miami"},
		{"time-series", "--destination", "203.0.113.1", "--source", "x"},
		{"time-series", "--destination", "203.0.113.1", "--source", ""}, // an empty value is not "both"
		{"time-series", "--destination", "203.0.113.1", "--samples", "-1"},
	} {
		if r := runCLI(t, env, args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
	}
}
