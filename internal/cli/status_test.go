package cli

import (
	"strings"
	"testing"
)

// ncfStatusFixtures adds the deployment-status and /stats routes to a fake.
func ncfStatusFixtures(api *fakeAPI) {
	api.json("GET /network-cloud-firewall/v1/acls/versions/deployment-status", 200, `{"accountId":"A-EXAMPLE","ruleSets":[
	  {"deploymentStatus":"PRODUCTION","version":7,"hash":"x","statusRetrievalTimestamp":"2026-10-14T09:00:00Z",
	   "rulesDeployStats":{"failed":1,"installed":10,"notInstalled":0,"total":11},"ruleSet":[]},
	  {"deploymentStatus":"PROCESSING","version":8,"rulesDeployStats":{"failed":0,"installed":0,"notInstalled":11,"total":11}}]}`)
	api.json("GET /network-cloud-firewall/v1/stats", 200, `{"aliases":[
	  {"type":"SOURCE","limit":100,"enabledCount":3,"disabledCount":1},
	  {"type":"BIG","limit":5,"enabledCount":1,"disabledCount":0}]}`)
}

func TestStatusUsesListOnly(t *testing.T) {
	api := ncfAPI(t)
	ncfStatusFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "status")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[StatusDoc](t, r.stdout, "prolexic.status.v1")
	if doc.Deployment.Version != 7 || doc.Deployment.FailedRules != 1 || !doc.Deployment.Processing || doc.Deployment.State != "PRODUCTION" {
		t.Errorf("deployment = %+v", doc.Deployment)
	}
	if len(doc.Aliases) != 2 || doc.Aliases[0].Name != "akamai-threats" || doc.Aliases[0].Editable || doc.Aliases[0].EntriesCount != 200000 ||
		doc.Aliases[1].Name != "block-v4" || doc.Aliases[1].ID != 101 || doc.Aliases[1].VersionsRemaining != nil {
		t.Errorf("aliases = %+v", doc.Aliases)
	}
	if len(doc.Limits) != 2 || doc.Limits[0].Type != "BIG" || doc.Limits[1].Limit != 100 || doc.Limits[1].Disabled != 1 {
		t.Errorf("limits = %+v", doc.Limits)
	}
	if strings.Contains(r.stdout, "versionsRemaining") {
		t.Error("versionsRemaining must be omitted when versions are not exposed")
	}
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/acls/aliases/") {
			t.Errorf("status fetched %s; it must only list", c.Path)
		}
	}
}

func TestStatusText(t *testing.T) {
	api := ncfAPI(t)
	ncfStatusFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "status", "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "deployment: version 7, state PRODUCTION, 1 failed rules, PROCESSING") ||
		!strings.Contains(r.stdout, "block-v4") {
		t.Errorf("exit %d, stdout:\n%s", r.code, r.stdout)
	}
}

func TestStatusDocText(t *testing.T) {
	// The markers need version data that NCF v1 can't supply, so render a
	// document directly.
	two, nine := 2, 9
	d := &StatusDoc{Aliases: []StatusAlias{
		{Name: "low", ActiveVersion: 8, ProdVersion: 8, VersionsRemaining: &two},
		{Name: "pending", ActiveVersion: 9, ProdVersion: 8, VersionsRemaining: &nine},
		{Name: "fine", ActiveVersion: 4, ProdVersion: 4, VersionsRemaining: &nine},
	}}
	var b strings.Builder
	if err := d.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(b.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "low"):
			if !strings.Contains(line, "LOW VERSIONS") || strings.Contains(line, "PENDING") {
				t.Errorf("low: %q", line)
			}
		case strings.HasPrefix(line, "pending"):
			if !strings.Contains(line, "ACTIVATION PENDING") || strings.Contains(line, "LOW") {
				t.Errorf("pending: %q", line)
			}
		case strings.HasPrefix(line, "fine"):
			if strings.Contains(line, "PENDING") || strings.Contains(line, "LOW") {
				t.Errorf("fine: %q", line)
			}
		}
	}
}
