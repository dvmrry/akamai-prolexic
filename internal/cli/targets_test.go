package cli

import (
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

const targetsFixture = `{"targets":[
  {"accountId":"A-CCT0000","createdBy":"user-a","createdTime":"2025-08-08T15:44:36Z","ports":[443,80],"targetDomain":"www.example.com","targetId":"21","targetIp":null,"targetName":"web-http","testIds":[1,3],"testType":"HTTP","extra":1},
  {"accountId":"A-CCT0000","ports":[80],"targetDomain":"","targetId":"20","targetIp":"203.0.113.10","targetName":"example-a-tcp","testType":"TCP"},
  {"accountId":"A-CCT0000","ports":[81],"targetId":"10","targetIp":"2001:db8::10","targetName":"example-a-tcp","testIds":[],"testType":"TCP"}
]}`

func TestTargetsList(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-network-health/v1/targets", 200, targetsFixture)
	r := runCLI(t, api.env(), "targets", "list")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.TargetsDoc](t, r.stdout, "prolexic.targets.v1")
	var ids []string
	for _, x := range doc.Targets {
		ids = append(ids, x.TargetID)
	}
	// By name, then id.
	if strings.Join(ids, " ") != "10 20 21" {
		t.Errorf("ids = %v", ids)
	}
	if x := doc.Targets[1]; x.TargetDomain != "" || x.TestIDs == nil || len(x.Ports) != 1 {
		t.Errorf("target = %+v", x)
	}
	if x := doc.Targets[2]; x.TargetIP != "" || x.TargetDomain != "www.example.com" || len(x.TestIDs) != 2 {
		t.Errorf("null ip target = %+v", x)
	}

	r = runCLI(t, api.env(), "targets", "list", "--format", "text")
	if !strings.Contains(r.stdout, "203.0.113.10") || !strings.Contains(r.stdout, "443,80") || !strings.Contains(r.stdout, "2001:db8::10") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestTargetsListEmpty(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-network-health/v1/targets", 200, `{"targets":[]}`)
	r := runCLI(t, api.env(), "targets", "list")
	doc := decode[ops.TargetsDoc](t, r.stdout, "prolexic.targets.v1")
	if r.code != 0 || doc.Targets == nil || len(doc.Targets) != 0 {
		t.Errorf("exit %d, targets %#v", r.code, doc.Targets)
	}
}

func TestTargetsShow(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-network-health/v1/targets/20", 200,
		`{"accountId":"A-CCT0000","ports":[80],"targetId":"20","targetIp":"203.0.113.10","targetName":"example-a-tcp","testIds":[3],"testType":"TCP"}`)
	api.json("GET /prolexic-network-health/v1/targets/99", 404,
		`{"type":"not_found","title":"Not Found","status":404,"detail":"Target not found","instance":"/prolexic-network-health/v1/targets/99"}`)

	r := runCLI(t, api.env(), "targets", "show", "--id", "20")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.TargetDoc](t, r.stdout, "prolexic.target.v1")
	if doc.Target.TargetID != "20" || doc.Target.TargetIP != "203.0.113.10" || doc.Target.TestIDs[0] != 3 {
		t.Errorf("target = %+v", doc.Target)
	}
	if r := runCLI(t, api.env(), "targets", "show", "--id", "20", "--format", "text"); !strings.Contains(r.stdout, "example-a-tcp") {
		t.Errorf("text:\n%s", r.stdout)
	}
	if r := runCLI(t, api.env(), "targets", "show", "--id", "99"); r.code != exitCode(apperr.NotFound) {
		t.Errorf("missing: exit = %d, want 4", r.code)
	}
	for _, args := range [][]string{{}, {"--id", "a/b"}} {
		if r := runCLI(t, api.env(), append([]string{"targets", "show"}, args...)...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
	}
	for _, c := range api.calls {
		if c.Method != "GET" {
			t.Errorf("non-GET call %s %s", c.Method, c.Path)
		}
	}
}
