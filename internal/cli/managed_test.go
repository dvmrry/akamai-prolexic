package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

const managedBase = "/network-cloud-firewall/v2/policy-domains/example-domain/managed-services-acls"

func managedFixtures(t *testing.T, api *fakeAPI) {
	api.json("GET "+managedBase+"/version", 200, `{"policyDomain":"example-domain","version":3,"state":"DEPLOYED","updatedBy":"example-user","ruleSet":[
	  {"index":1,"aclText":"permit ip any 203.0.113.0/24","destination":"203.0.113.0/24","ipVersion":"V4","locations":["DC-A","DC-B"],"ruleUuid":"`+ruleB+`"},
	  {"index":0,"aclText":"permit ip any any","anyDestination":true,"ipVersion":"V6","ruleUuid":"`+ruleA+`"}]}`)
	api.json("GET "+managedBase+"/rule-hits", 200, `{"policyDomain":"example-domain","rules":[
	  {"ruleUuid":"`+ruleB+`","matches":4,"bytes":40},{"ruleUuid":"`+ruleA+`","matches":8,"bytes":80,"lastMatch":"2026-10-14T08:00:00Z"}]}`)
	api.routes["GET "+managedBase+"/rule-hits/rules/"+ruleA+"/time-series"] = func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("startTime") != "2026-10-13T09:00:00Z" || q.Get("endTime") != "2026-10-14T09:00:00Z" {
			t.Errorf("window = %s .. %s", q.Get("startTime"), q.Get("endTime"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"policyDomain":"example-domain","resolution":"1d","totalMatches":8,"averageMatches":8,"peakMatches":8.0,
		  "timeSeries":[{"timestamp":"2026-10-13T00:00:00Z","matches":8,"bytes":80}]}`))
	}
}

func TestManagedACL(t *testing.T) {
	api := newFakeAPI(t)
	managedFixtures(t, api)
	r := runCLI(t, ncfEnv(api.env()), "managed", "acl", "--policy-domain", "example-domain")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ops.ManagedACLDoc](t, r.stdout, "prolexic.managed-acl.v1")
	if doc.PolicyDomain != "example-domain" || doc.Version != 3 || len(doc.Rules) != 2 || doc.Rules[0].Index != 0 || !doc.Rules[0].AnyDestination ||
		doc.Rules[0].Locations == nil || len(doc.Rules[1].Locations) != 2 {
		t.Errorf("doc = %+v", doc)
	}
	if r := runCLI(t, ncfEnv(api.env()), "managed", "acl", "--policy-domain", "example-domain", "--format", "text"); !strings.Contains(r.stdout, "managed ACL version 3") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestManagedRuleHits(t *testing.T) {
	api := newFakeAPI(t)
	managedFixtures(t, api)
	r := runCLI(t, ncfEnv(api.env()), "managed", "rule-hits", "--policy-domain", "example-domain")
	doc := decode[ops.ManagedRuleHitsDoc](t, r.stdout, "prolexic.managed-rule-hits.v1")
	if r.code != 0 || len(doc.Rules) != 2 || doc.Rules[0].RuleID != ruleA || doc.Rules[0].Matches != 8 || doc.Series != nil {
		t.Fatalf("exit %d, doc = %+v", r.code, doc)
	}
	// One rule: the series defaults to the last 24 hours.
	r = runCLI(t, ncfEnv(api.env()), "managed", "rule-hits", "--policy-domain", "example-domain", "--rule", ruleA)
	doc = decode[ops.ManagedRuleHitsDoc](t, r.stdout, "prolexic.managed-rule-hits.v1")
	if r.code != 0 || len(doc.Rules) != 1 || doc.Series == nil || doc.Series.Resolution != "1d" || len(doc.Series.Points) != 1 {
		t.Errorf("exit %d, doc = %+v", r.code, doc)
	}
}

func TestManagedUsage(t *testing.T) {
	api := newFakeAPI(t)
	managedFixtures(t, api)
	for _, args := range [][]string{
		{"managed", "acl"},
		{"managed", "acl", "--policy-domain", "a/b"},
		{"managed", "rule-hits", "--policy-domain", "example-domain", "--since", "1h"}, // a window needs --rule
	} {
		if r := runCLI(t, ncfEnv(api.env()), args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d", args, r.code)
		}
	}
	if r := runCLI(t, ncfEnv(api.env()), "managed", "rule-hits", "--policy-domain", "example-domain", "--rule", "cccccccc"); r.code != exitCode(apperr.NotFound) {
		t.Errorf("unknown rule: exit = %d", r.code)
	}
}

func TestManagedRuleHitsSeries404IsAnEmptyWindow(t *testing.T) {
	api := newFakeAPI(t)
	managedFixtures(t, api)
	api.json("GET "+managedBase+"/rule-hits/rules/"+ruleA+"/time-series", 404, `{"title":"Not Found","status":404}`)
	r := runCLI(t, ncfEnv(api.env()), "managed", "rule-hits", "--policy-domain", "example-domain", "--rule", ruleA)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ops.ManagedRuleHitsDoc](t, r.stdout, "prolexic.managed-rule-hits.v1")
	if doc.Series == nil || doc.Series.TotalMatches != 0 || doc.Series.Points == nil || len(doc.Series.Points) != 0 {
		t.Errorf("series = %+v", doc.Series)
	}
}
