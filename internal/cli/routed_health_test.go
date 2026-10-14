package cli

import (
	"strings"
	"testing"
)

const healthFixture = `[
  {"akamaiLocation":"LOC-B","routerName":"edge-2","healthyFunnels":2,"totalFunnels":2},
  {"akamaiLocation":"LOC-A","routerName":"edge-1","healthyFunnels":1,"totalFunnels":2,"healthyAdcFunnels":0,"totalAdcFunnels":0}
]`

func TestRoutedHealth(t *testing.T) {
	api := newFakeAPI(t)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/health", 200, healthFixture)

	r := runCLI(t, api.env(), "routed", "health", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[RoutedHealthDoc](t, r.stdout, "prolexic.routed-health.v1")
	if len(doc.Health) != 2 || doc.Health[0].AkamaiLocation != "LOC-A" || doc.Health[0].Customer != "example-a" ||
		doc.Health[0].HealthyFunnels != 1 || doc.Health[0].TotalFunnels != 2 {
		t.Errorf("health = %+v", doc.Health)
	}

	r = runCLI(t, api.env(), "routed", "health", "--customer", "example-a", "--format", "text")
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "1/2") || !strings.Contains(lines[1], "UNHEALTHY") || strings.Contains(lines[2], "UNHEALTHY") {
		t.Errorf("text:\n%s", r.stdout)
	}
}
