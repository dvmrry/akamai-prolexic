package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const analyzerRoute = "POST /network-cloud-firewall/v2/acls/analyzer/test"

type analyzerReq struct {
	Rules []struct {
		Index     int    `json:"index"`
		ACLText   string `json:"aclText"`
		IPVersion string `json:"ipVersion"`
	} `json:"rules"`
	PacketTests []map[string]any `json:"packetTests"`
}

// analyzerFixtures serves production version 7 (original indexes 0, 4, 7, 9,
// 12: a remark, a V6 rule, two V4 rules and a V4 deny-all) and a fake analyzer
// that matches the first rule naming the packet's protocol (or "ip") and
// otherwise permits implicitly.
func analyzerFixtures(api *fakeAPI) {
	api.json("GET "+aclBase+"/deployment-status", 200, `{"ruleSets":[{"deploymentStatus":"PRODUCTION","version":7}]}`)
	api.json("GET "+aclBase+"/7", 200, `{"version":7,"state":"DEPLOYED","ruleSet":[
	  {"index":12,"ipVersion":"V4","aclText":"deny ip any 198.51.100.0/24","parsed":{"action":"deny"}},
	  {"index":9,"ipVersion":"V4","aclText":"permit udp any 198.51.100.0/24 eq 53","comment":"dns","parsed":{"action":"permit"}},
	  {"index":0,"aclText":"remark example"},
	  {"index":4,"ipVersion":"V6","aclText":"deny ipv6 any 2001:db8::/32","parsed":{"action":"deny"}},
	  {"index":7,"ipVersion":"V4","aclText":"deny tcp 192.0.2.0/24 198.51.100.0/24 eq 443","parsed":{"action":"deny"}}]}`)
	api.json("GET "+aclBase+"/8", 200, `{"version":8,"state":"CONFIGURATION","ruleSet":[{"index":1,"ipVersion":"V4","aclText":"permit ip any any"}]}`)
	api.routes[analyzerRoute] = func(w http.ResponseWriter, r *http.Request) {
		var req analyzerReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(400)
			return
		}
		var results []map[string]any
		allowed, denied := 0, 0
		for _, p := range req.PacketTests {
			res := map[string]any{"packetId": p["packetId"], "decision": "ALLOW", "implicitPermit": true, "matchedRule": nil}
			for _, rule := range req.Rules {
				fields := strings.Fields(rule.ACLText)
				if len(fields) > 1 && (fields[1] == p["protocol"] || fields[1] == "ip") {
					res["matchedRule"] = map[string]any{"index": rule.Index, "aclText": rule.ACLText}
					res["implicitPermit"] = false
					if fields[0] == "deny" {
						res["decision"] = "DENY"
					}
					break
				}
			}
			if res["decision"] == "ALLOW" {
				allowed++
			} else {
				denied++
			}
			results = append(results, res)
		}
		reply(w, 200, map[string]any{"analysisType": "PACKET_TESTING", "results": results,
			"summary": map[string]any{"totalPackets": len(results), "allowed": allowed, "denied": denied}})
	}
}

func lastAnalyzerReq(t *testing.T, api *fakeAPI) analyzerReq {
	t.Helper()
	for i := len(api.calls) - 1; i >= 0; i-- {
		if api.calls[i].Method == "POST" {
			var req analyzerReq
			if err := json.Unmarshal([]byte(api.calls[i].Body), &req); err != nil {
				t.Fatal(err)
			}
			return req
		}
	}
	t.Fatal("no analyzer call")
	return analyzerReq{}
}

func TestACLTestProductionRenumbersAndMapsBack(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--src", "192.0.2.9", "--dst", "198.51.100.5", "--proto", "tcp", "--dport", "443")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ACLTestDoc](t, r.stdout, "prolexic.acl-test.v1")
	if doc.Version != 7 || !doc.Production || doc.IPVersion != "V4" || doc.RulesTested != 4 || len(doc.Results) != 1 {
		t.Fatalf("doc = %+v", doc)
	}
	res := doc.Results[0]
	// The analyzer saw the tcp rule at 2; its original index is 7.
	if res.Packet.PacketID != "p1" || res.Decision != "DENY" || res.Rule == nil || res.Rule.Index != 7 || !strings.HasPrefix(res.Rule.ACLText, "deny tcp") {
		t.Errorf("result = %+v rule %+v", res, res.Rule)
	}
	req := lastAnalyzerReq(t, api)
	if len(req.Rules) != 4 {
		t.Fatalf("sent %d rules: %+v", len(req.Rules), req.Rules)
	}
	for i, rule := range req.Rules {
		if rule.Index != i+1 || rule.IPVersion != "V4" {
			t.Errorf("rule %d = %+v", i, rule)
		}
	}
	if req.Rules[0].ACLText != "remark example" || req.Rules[1].ACLText != "deny tcp 192.0.2.0/24 198.51.100.0/24 eq 443" {
		t.Errorf("order: %+v", req.Rules)
	}
}

func TestACLTestIPv6SelectsV6Rules(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--src", "2001:db8::1", "--dst", "2001:db8:1::5", "--proto", "ipv6")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ACLTestDoc](t, r.stdout, "prolexic.acl-test.v1")
	if doc.IPVersion != "V6" || doc.RulesTested != 2 || doc.Results[0].Rule == nil || doc.Results[0].Rule.Index != 4 {
		t.Errorf("doc = %+v", doc)
	}
	if req := lastAnalyzerReq(t, api); len(req.Rules) != 2 || req.Rules[1].Index != 2 || req.Rules[1].IPVersion != "V6" {
		t.Errorf("sent %+v", req.Rules)
	}
}

func TestACLTestVersionFlagAndText(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--version", "8", "--src", "192.0.2.9", "--dst", "198.51.100.5")
	doc := decode[ACLTestDoc](t, r.stdout, "prolexic.acl-test.v1")
	if r.code != 0 || doc.Version != 8 || doc.Production || doc.Results[0].Rule == nil || doc.Results[0].Rule.Index != 1 {
		t.Errorf("exit %d doc = %+v", r.code, doc)
	}
	r = runCLI(t, ncfEnv(api.env()), "acl", "test", "--src", "192.0.2.9", "--dst", "198.51.100.5", "--proto", "gre", "--format", "text")
	for _, want := range []string{"ACL version 7 (production), 4 V4 rules tested", "PACKET", "p1", "gre 192.0.2.9 -> 198.51.100.5", "DENY", "#12 deny ip any 198.51.100.0/24"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("text lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestACLTestImplicitPermit(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	api.json("GET "+aclBase+"/8", 200, `{"version":8,"ruleSet":[{"index":3,"ipVersion":"V4","aclText":"deny udp any any"}]}`)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--version", "8", "--src", "192.0.2.9", "--dst", "198.51.100.5", "--proto", "tcp", "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "implicit permit") || !strings.Contains(r.stdout, "1 allowed, 0 denied") {
		t.Errorf("exit %d:\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestACLTestPacketsFile(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	file := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(file, []byte(`[{"protocol":"udp","srcIp":"203.0.113.7","dstIp":"198.51.100.5","dstPort":53},
	  {"packetId":"web","protocol":"tcp","srcIp":"192.0.2.9","dstIp":"198.51.100.5","dstPort":443,"tcpFlags":["syn"]}]`), 0o600)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--packets", file)
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[ACLTestDoc](t, r.stdout, "prolexic.acl-test.v1")
	if len(doc.Results) != 2 || doc.Results[0].Packet.PacketID != "p1" || doc.Results[1].Packet.PacketID != "web" ||
		doc.Results[0].Rule.Index != 9 || doc.Results[1].Rule.Index != 7 || doc.Summary.Denied != 1 || doc.Summary.Allowed != 1 {
		t.Errorf("doc = %+v", doc)
	}
	if req := lastAnalyzerReq(t, api); req.PacketTests[0]["packetId"] != "p1" {
		t.Errorf("sent %+v", req.PacketTests)
	}
}

func TestACLTestUsageErrors(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	one := `{"protocol":"ip","srcIp":"192.0.2.1","dstIp":"198.51.100.1"}`
	arr := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat(one+",", n), ",") + "]" }
	cases := map[string][]string{
		"no src":        {"--dst", "198.51.100.1"},
		"not an ip":     {"--src", "nope", "--dst", "198.51.100.1"},
		"mixed family":  {"--src", "192.0.2.1", "--dst", "2001:db8::1"},
		"bad proto":     {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--proto", "sctp"},
		"port on ip":    {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--dport", "80"},
		"flags on udp":  {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--proto", "udp", "--flags", "syn"},
		"bad flag":      {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--proto", "tcp", "--flags", "syn,zap"},
		"port range":    {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--proto", "tcp", "--dport", "70000"},
		"ttl zero":      {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--ttl", "0"},
		"est and frag":  {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--proto", "tcp", "--established", "--fragment"},
		"negative ver":  {"--src", "192.0.2.1", "--dst", "198.51.100.1", "--version", "-1"},
		"six packets":   {"--packets", write("six.json", arr(6))},
		"empty array":   {"--packets", write("empty.json", "[]")},
		"unknown field": {"--packets", write("unk.json", `[{"protocol":"ip","srcIp":"192.0.2.1","dstIp":"198.51.100.1","bogus":1}]`)},
		"not an array":  {"--packets", write("obj.json", `{"protocol":"ip"}`)},
		"mixed packets": {"--packets", write("mix.json", `[`+one+`,{"protocol":"ip","srcIp":"2001:db8::1","dstIp":"2001:db8::2"}]`)},
		"dup ids":       {"--packets", write("dup.json", `[{"packetId":"a","protocol":"ip","srcIp":"192.0.2.1","dstIp":"198.51.100.1"},{"packetId":"a","protocol":"ip","srcIp":"192.0.2.1","dstIp":"198.51.100.1"}]`)},
		"file and flag": {"--packets", write("ok.json", arr(1)), "--src", "192.0.2.1"},
	}
	for name, args := range cases {
		r := runCLI(t, ncfEnv(api.env()), append([]string{"acl", "test"}, args...)...)
		if r.code != int(apperr.Usage) {
			t.Errorf("%s: exit = %d: %s%s", name, r.code, r.stdout, r.stderr)
		}
	}
	for _, c := range api.calls {
		if c.Method == "POST" {
			t.Errorf("a rejected packet reached the API: %s", c.Body)
		}
	}
	// Five packets are accepted.
	if r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--packets", write("five.json", arr(5))); r.code != 0 {
		t.Errorf("five packets: exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
}

func TestACLTest403IsCredentials(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	api.json(analyzerRoute, 403, `{"errorCode":"INSUFFICIENT_PRIVILEGES","message":"You do not have permission to perform this action."}`)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--src", "192.0.2.9", "--dst", "198.51.100.5")
	if r.code != int(apperr.Credentials) || !strings.Contains(r.stderr+r.stdout, "different API grant") {
		t.Errorf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
}

func TestACLTestNoRulesOfFamily(t *testing.T) {
	api := newFakeAPI(t)
	analyzerFixtures(api)
	api.json("GET "+aclBase+"/8", 200, `{"version":8,"ruleSet":[{"index":1,"ipVersion":"V6","aclText":"permit ipv6 any any"}]}`)
	r := runCLI(t, ncfEnv(api.env()), "acl", "test", "--version", "8", "--src", "192.0.2.9", "--dst", "198.51.100.5")
	if r.code != int(apperr.NotFound) {
		t.Errorf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
}
