package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const aclBase = "/network-cloud-firewall/v2/acls/versions"

// aclFixtures serves a production version 7, a staged 8 and a failed 6, with
// the version list on two pages.
func aclFixtures(api *fakeAPI) {
	api.routes["GET "+aclBase] = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "0" {
			w.Write([]byte(`{"content":[{"version":6,"state":"DEPRECATED","rulesCount":9},
			  {"version":8,"state":"CONFIGURATION","rulesCount":11,"description":"staged","updatedBy":"example-user","updatedTimestamp":"2026-10-14T08:00:00Z"}],"last":false,"totalPages":2}`))
			return
		}
		w.Write([]byte(`{"content":[{"version":7,"state":"DEPLOYED","rulesCount":10}],"last":true,"totalPages":2}`))
	}
	api.routes["GET "+aclBase+"/7"] = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") != "true" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":7,"state":"DEPLOYED","ruleSet":[
		  {"index":2,"ipVersion":"V4","aclText":"permit udp allow-v6 any eq 53","comment":"dns","parsed":{"action":"permit","ipVersion":"v4",
		   "sourceAddress":"SRC::A-EXAMPLE::allow-v6","destinationAddress":"any","protocol":{"min":17,"max":17},"udp":{"destinationPort":{"min":53,"max":53}}}},
		  {"index":0,"aclText":"remark example","comment":"example remark"},
		  {"index":1,"ipVersion":"V4","aclText":"deny ip block-v4 protected-dst","parsed":{"action":"deny","sourceAddress":"SRC::A-EXAMPLE::block-v4",
		   "destinationAddress":"protected-dst","protocol":{"min":0,"max":255}}},
		  {"index":3,"parsed":{"action":"deny","sourceAddress":"192.0.2.0/24","destinationAddress":"198.51.100.0/24","protocol":{"min":6,"max":6},
		   "tcp":{"sourcePort":{"min":1024,"max":65535},"destinationPort":{"min":80,"max":443}}}}]}`))
	}
	api.routes["GET "+aclBase+"/8"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":8,"state":"CONFIGURATION"}`))
	}
	api.json("GET "+aclBase+"/deployment-status", 200, `{"accountId":"A-EXAMPLE","ruleSets":[
	  {"deploymentStatus":"PRODUCTION","version":7,"hash":"x","statusRetrievalTimestamp":"2026-10-14T09:00:00Z",
	   "rulesDeployStats":{"failed":1,"installed":9,"notInstalled":0,"total":10},
	   "ruleSet":[{"aclText":"deny ip block-v4 protected-dst","installStatus":"FAILED","ruleUuid":"11111111-1111-1111-1111-111111111111"}]},
	  {"deploymentStatus":"PROCESSING","version":8,"rulesDeployStats":{"failed":0,"installed":0,"notInstalled":11,"total":11}}]}`)
}

func TestACLVersions(t *testing.T) {
	api := newFakeAPI(t)
	aclFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "versions")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ACLVersionsDoc](t, r.stdout, "prolexic.acl-versions.v1")
	if len(doc.Versions) != 3 || doc.Versions[0].Version != 8 || doc.Versions[1].Version != 7 || doc.Versions[2].Version != 6 ||
		doc.Versions[0].Description != "staged" || doc.Versions[1].State != "DEPLOYED" {
		t.Errorf("versions = %+v", doc.Versions)
	}
}

func TestACLShowDefaultsToProduction(t *testing.T) {
	api := newFakeAPI(t)
	aclFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "show")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ACLDoc](t, r.stdout, "prolexic.acl.v1")
	if doc.Version != 7 || !doc.Production || len(doc.Rules) != 4 {
		t.Fatalf("doc = %+v", doc)
	}
	for i, r := range doc.Rules {
		if r.Index != i {
			t.Errorf("rule %d has index %d: not in index order", i, r.Index)
		}
	}
	remark, deny, permit, tcp := doc.Rules[0], doc.Rules[1], doc.Rules[2], doc.Rules[3]
	if remark.Action != "" || remark.Comment != "example remark" {
		t.Errorf("remark = %+v", remark)
	}
	if deny.Action != "deny" || deny.Source != "SRC::A-EXAMPLE::block-v4" || deny.Destination != "protected-dst" || deny.Protocol != "ip" {
		t.Errorf("deny = %+v", deny)
	}
	if permit.Protocol != "udp" || permit.DestinationPorts != "53" || permit.Comment != "dns" || permit.IPVersion != "V4" {
		t.Errorf("permit = %+v", permit)
	}
	if tcp.Protocol != "tcp" || tcp.SourcePorts != "1024-65535" || tcp.DestinationPorts != "80-443" {
		t.Errorf("tcp = %+v", tcp)
	}
}

func TestACLShowVersionAndText(t *testing.T) {
	api := newFakeAPI(t)
	aclFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "show", "--version", "8")
	doc := decode[ACLDoc](t, r.stdout, "prolexic.acl.v1")
	if r.code != 0 || doc.Version != 8 || doc.Production || doc.Rules == nil || len(doc.Rules) != 0 {
		t.Errorf("exit %d, doc = %+v", r.code, doc)
	}
	r = runCLI(t, ncfEnv(api.env()), "acl", "show", "--format", "text")
	if !strings.Contains(r.stdout, "ACL version 7, state DEPLOYED (production), 4 rules") || !strings.Contains(r.stdout, "protected-dst") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestACLShowNothingInProduction(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET "+aclBase+"/deployment-status", 200, `{"ruleSets":[{"deploymentStatus":"PROCESSING","version":8}]}`)
	if r := runCLI(t, ncfEnv(api.env()), "acl", "show"); r.code != exitCode(apperr.NotFound) {
		t.Errorf("exit = %d: %s", r.code, r.stderr)
	}
}

func TestACLDeployment(t *testing.T) {
	api := newFakeAPI(t)
	aclFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "deployment")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ACLDeploymentDoc](t, r.stdout, "prolexic.acl-deployment.v1")
	// Newest version first: processing 8, then production 7.
	if doc.Production != 7 || len(doc.RuleSets) != 2 || doc.RuleSets[1].Stats.Failed != 1 ||
		doc.RuleSets[1].Rules[0].InstallStatus != "FAILED" || doc.RuleSets[0].Status != "PROCESSING" || doc.RuleSets[0].Rules == nil {
		t.Errorf("doc = %+v", doc)
	}
	r = runCLI(t, ncfEnv(api.env()), "acl", "deployment", "--format", "text")
	if !strings.Contains(r.stdout, "<- production") {
		t.Errorf("text:\n%s", r.stdout)
	}
}
