package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const (
	hitsBase = "/network-cloud-firewall/v2/rule-hits/rules"
	ruleA    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	ruleB    = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

func ruleHitsFixtures(t *testing.T, api *fakeAPI) {
	api.json("GET "+hitsBase, 200, `{"rulesetName":"example-ruleset","rulesetType":"ACCOUNT","rules":[
	  {"ruleId":"`+ruleB+`","matches":5,"bytes":500,"firstMatch":"2026-10-01T00:00:00Z","lastMatch":"2026-10-14T08:00:00Z"},
	  {"ruleId":"`+ruleA+`","matches":12,"bytes":1200,"lastReset":"2026-09-01T00:00:00Z","lastUpdated":"2026-10-14T08:55:00Z"}]}`)
	api.json("GET "+hitsBase+"/"+ruleA, 200, `{"ruleId":"`+ruleA+`","matches":12,"bytes":1200,"lastMatch":"2026-10-14T08:00:00Z"}`)
	api.routes["GET "+hitsBase+"/"+ruleA+"/time-series"] = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("startTime") != "2026-10-13T09:00:00Z" || q.Get("endTime") != "2026-10-14T09:00:00Z" {
			t.Errorf("window = %s .. %s", q.Get("startTime"), q.Get("endTime"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ruleUuid":"` + ruleA + `","startTime":"2026-10-13T09:00:00Z","endTime":"2026-10-14T09:00:00Z","resolution":"1h",
		  "totalMatches":12,"averageMatches":6,"peakMatches":9,
		  "timeSeries":[{"timestamp":"2026-10-14T01:00:00Z","matches":9,"bytes":900},{"timestamp":"2026-10-13T20:00:00Z","matches":3,"bytes":300}]}`))
	}
}

func TestRuleHitsList(t *testing.T) {
	api := newFakeAPI(t)
	ruleHitsFixtures(t, api)
	r := runCLI(t, ncfEnv(api.env()), "rule-hits", "list")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[RuleHitsDoc](t, r.stdout, "prolexic.rule-hits.v1")
	if doc.RulesetName != "example-ruleset" || len(doc.Rules) != 2 || doc.Rules[0].RuleID != ruleA || doc.Rules[0].Matches != 12 || doc.Rules[1].Bytes != 500 {
		t.Errorf("doc = %+v", doc)
	}
	if r := runCLI(t, ncfEnv(api.env()), "rule-hits", "list", "--format", "text"); !strings.Contains(r.stdout, ruleA) {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestRuleHitsShow(t *testing.T) {
	api := newFakeAPI(t)
	ruleHitsFixtures(t, api)
	r := runCLI(t, ncfEnv(api.env()), "rule-hits", "show", "--rule", ruleA)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[RuleHitDoc](t, r.stdout, "prolexic.rule-hit.v1")
	if doc.Rule.RuleID != ruleA || doc.Rule.Matches != 12 || doc.Series != nil {
		t.Errorf("no window: doc = %+v", doc)
	}
	for _, c := range api.calls {
		if strings.HasSuffix(c.Path, "/time-series") {
			t.Error("fetched the time series without a window")
		}
	}

	r = runCLI(t, ncfEnv(api.env()), "rule-hits", "show", "--rule", ruleA, "--since", "24h")
	doc = decode[RuleHitDoc](t, r.stdout, "prolexic.rule-hit.v1")
	if r.code != 0 || doc.Series == nil || doc.Series.Resolution != "1h" || doc.Series.TotalMatches != 12 || doc.Series.PeakMatches != 9 ||
		len(doc.Series.Points) != 2 || doc.Series.Points[0].Matches != 3 {
		t.Errorf("with window: exit %d, doc = %+v", r.code, doc)
	}
	r = runCLI(t, ncfEnv(api.env()), "rule-hits", "show", "--rule", ruleA, "--since", "24h", "--format", "text")
	if !strings.Contains(r.stdout, "resolution 1h") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestRuleHitsShowUsage(t *testing.T) {
	api := newFakeAPI(t)
	ruleHitsFixtures(t, api)
	for _, args := range [][]string{
		{"rule-hits", "show"},
		{"rule-hits", "show", "--rule", "a/b"},
		{"rule-hits", "show", "--rule", ruleA, "--since", "1h", "--start", "2026-10-14T00:00:00Z"},
	} {
		if r := runCLI(t, ncfEnv(api.env()), args...); r.code != int(apperr.Usage) {
			t.Errorf("%v: exit = %d", args, r.code)
		}
	}
	if r := runCLI(t, ncfEnv(api.env()), "rule-hits", "show", "--rule", ruleB); r.code != int(apperr.NotFound) {
		t.Errorf("unknown rule: exit = %d", r.code)
	}
}

func TestRuleHitsRejectsDotPathSegments(t *testing.T) {
	api := newFakeAPI(t)
	for _, id := range []string{".", ".."} {
		r := runCLI(t, api.env(), "rule-hits", "show", "--rule", id)
		if r.code != int(apperr.Usage) || len(api.calls) != 0 {
			t.Errorf("--rule %q: exit = %d, calls = %d", id, r.code, len(api.calls))
		}
	}
}

func TestRuleHitsShowSeries404IsAnEmptyWindow(t *testing.T) {
	api := newFakeAPI(t)
	ruleHitsFixtures(t, api)
	api.json("GET "+hitsBase+"/"+ruleA+"/time-series", 404, `{"title":"Not Found","status":404}`)
	r := runCLI(t, ncfEnv(api.env()), "rule-hits", "show", "--rule", ruleA, "--since", "24h")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[RuleHitDoc](t, r.stdout, "prolexic.rule-hit.v1")
	if doc.Series == nil || doc.Series.TotalMatches != 0 || doc.Series.Points == nil || len(doc.Series.Points) != 0 {
		t.Errorf("series = %+v", doc.Series)
	}
}
