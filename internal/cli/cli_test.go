package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/pflag"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// fakeAPI is an Akamai API stand-in: routes map "METHOD /path" to a handler.
// Every request it serves is recorded. Fixtures are synthetic: example names
// and documentation address ranges only.
type fakeAPI struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	calls  []call
	// intercept, if set, sees every request first and answers it by returning
	// true.
	intercept func(http.ResponseWriter, *http.Request) bool
}

type call struct {
	Method, Path string
	Body         string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, routes: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	// Explicit --customer names are checked against the account's names; by
	// default the account has every synthetic name the tests use. A test that
	// registers its own route replaces this one.
	f.json("GET /prolexic-analytics/v2/customer/names", 200, `{"customerNames":[
	  {"name":"example-a","contractId":"C-EXAMPLE","accountName":"Example","inUse":true},
	  {"name":"example-b","contractId":"C-EXAMPLE","accountName":"Example","inUse":true},
	  {"name":"example-c","contractId":"C-EXAMPLE","accountName":"Example","inUse":true},
	  {"name":"example-bad","contractId":"C-EXAMPLE","accountName":"Example","inUse":true},
	  {"name":"example-old","contractId":"C-EXAMPLE","accountName":"Example","inUse":false},
	  {"name":"example a","contractId":"C-EXAMPLE","accountName":"Example","inUse":true}]}`)
	return f
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, call{r.Method, r.URL.Path, string(body)})
	h, ok := f.routes[r.Method+" "+r.URL.Path]
	intercept := f.intercept
	f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "EG1-HMAC-SHA256 ") {
		f.t.Errorf("%s %s: unsigned", r.Method, r.URL.Path)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	switch {
	case intercept != nil && intercept(w, r):
	case ok:
		h(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"type":"not-found","title":"Not Found","detail":"no fake route"}`))
	}
}

// json registers a route that answers with a fixed JSON body.
func (f *fakeAPI) json(route string, status int, body string) {
	f.routes[route] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

// env returns an Env whose read credentials point at the fake.
func (f *fakeAPI) env() Env {
	vars := map[string]string{
		"AKAMAI_HOST":          strings.TrimPrefix(f.srv.URL, "http://"),
		"AKAMAI_CLIENT_TOKEN":  "akab-client-token-xxx-xxxxxxxxxxxxxxxx",
		"AKAMAI_CLIENT_SECRET": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
		"AKAMAI_ACCESS_TOKEN":  "akab-access-token-xxx-xxxxxxxxxxxxxxxx",
	}
	return Env{Getenv: func(k string) string { return vars[k] }, Scheme: "http"}
}

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, env Env, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env.Stdout, env.Stderr = &stdout, &stderr
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.Home == "" {
		env.Home = t.TempDir() // never the developer's real ~/.edgerc
	}
	code := Run(context.Background(), args, env)
	return result{code, stdout.String(), stderr.String()}
}

// decode unmarshals JSON output and checks its schema id.
func decode[T any](t *testing.T, s, schema string) T {
	t.Helper()
	var head struct{ Schema string }
	if err := json.Unmarshal([]byte(s), &head); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	if head.Schema != schema {
		t.Fatalf("schema = %q, want %q", head.Schema, schema)
	}
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   apperr.Kind
		wantStdout string
		wantStderr string
	}{
		{"no args", nil, apperr.Usage, "", "missing command"},
		{"help", []string{"--help"}, apperr.OK, "Available Commands:", ""},
		{"help command", []string{"help", "plan"}, apperr.OK, "apply --expect-digest takes that digest", ""},
		{"group without subcommand", []string{"routed"}, apperr.Usage, "", `missing subcommand for "prolexic routed"; run 'prolexic routed --help'`},
		{"unknown subcommand", []string{"routed", "bogus"}, apperr.Usage, "", `unknown command "bogus" for "prolexic routed"`},
		{"unknown", []string{"bogus"}, apperr.Usage, "", `unknown command "bogus"; run 'prolexic --help'`},
		{"version", []string{"version"}, apperr.OK, `"schema": "prolexic.version.v1"`, ""},
		{"--version", []string{"--version", "--format", "text"}, apperr.OK, "prolexic ", ""},
		{"bad flag", []string{"version", "--nope"}, apperr.Usage, "", "unknown flag: --nope"},
		{"missing required flag", []string{"plan"}, apperr.Usage, "", `required flag(s) "file" not set; run 'prolexic plan --help'`},
		{"too few arguments", []string{"add", "--file", "f", "--ticket", "T", "--reason", "r", "block-v4"}, apperr.Usage, "", "requires at least 2 arg(s)"},
		{"bad format", []string{"version", "--format", "yaml"}, apperr.Usage, "", "--format must be"},
		{"flag help", []string{"routed", "sessions", "-h"}, apperr.OK, "-customer", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runCLI(t, Env{}, tt.args...)
			if r.code != exitCode(tt.wantCode) {
				t.Errorf("exit = %d, want %s\nstderr: %s", r.code, tt.wantCode, r.stderr)
			}
			if !strings.Contains(r.stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want %q", r.stdout, tt.wantStdout)
			}
			if !strings.Contains(r.stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want %q", r.stderr, tt.wantStderr)
			}
		})
	}
}

// stderr is text for people unless --format json asks for the error document.
func TestErrorDocumentOnStderr(t *testing.T) {
	if r := runCLI(t, Env{}, "bogus"); !strings.HasPrefix(r.stderr, "prolexic: unknown command") || strings.Contains(r.stderr, "Usage:") {
		t.Errorf("default stderr = %q, want one line of text", r.stderr)
	}
	r := runCLI(t, Env{}, "bogus", "--format", "json")
	doc := decode[struct {
		Code int
		Kind string
	}](t, r.stderr, "prolexic.error.v1")
	if doc.Code != 2 || doc.Kind != "usage" {
		t.Errorf("error doc = %+v", doc)
	}
}

func TestDoctor(t *testing.T) {
	home := t.TempDir()
	edgerc := "[default]\nhost = h.example\nclient_token = akab-ct\nclient_secret = SECRETVALUE\naccess_token = akab-at\n"
	if err := os.WriteFile(filepath.Join(home, ".edgerc"), []byte(edgerc), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, Env{Home: home}, "doctor")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	if strings.Contains(r.stdout, "SECRETVALUE") || strings.Contains(r.stdout, "h.example") {
		t.Errorf("doctor leaked a value: %s", r.stdout)
	}
	doc := decode[DoctorDoc](t, r.stdout, "prolexic.doctor.v1")
	if !doc.Clients[0].Resolved || doc.Clients[0].Source.Kind != "edgerc" || doc.Clients[1].Resolved {
		t.Errorf("clients = %+v", doc.Clients)
	}

	r = runCLI(t, Env{}, "doctor")
	if r.code != exitCode(apperr.Credentials) {
		t.Errorf("no credentials: exit = %d, want 3", r.code)
	}
}

const sessionsFixture = `[
  {"asn": 64500, "dataCenter": "DC-B", "routerName": "edge-2", "tunnelType": "GRE",
   "akamaiGreEndpointIpv4": "192.0.2.1", "customerGreEndpointIpv4": "198.51.100.1",
   "akamaiBgpPeerIpv4": "192.0.2.5", "customerBgpPeerIpv4": "192.0.2.6", "healthIpv4": "UP",
   "notInSpec": "ignored"},
  {"asn": 64500, "dataCenter": "DC-A", "routerName": "edge-1",
   "akamaiGreEndpointIpv4": "192.0.2.9", "customerGreEndpointIpv4": "198.51.100.2",
   "akamaiBgpPeerIpv4": "192.0.2.13", "customerBgpPeerIpv4": "192.0.2.14", "healthIpv4": "DOWN",
   "customerBgpPeerIpv6": "2001:db8::2"}
]`

func TestRoutedSessionsResolvesNamesAndSorts(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/customer/names", 200, `{"customerNames":[
		{"name":"example-b","contractId":"C-1","accountName":"Example","inUse":true},
		{"name":"example-a","contractId":"C-1","accountName":"Example","inUse":true},
		{"name":"example-old","contractId":"C-1","accountName":"Example","inUse":false}]}`)
	api.routes["POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions"] = func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CustomerNames []string }
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.CustomerNames) == 1 && req.CustomerNames[0] == "example-a" {
			w.Write([]byte(sessionsFixture))
			return
		}
		w.Write([]byte(`[]`))
	}

	r := runCLI(t, api.env(), "routed", "sessions")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[RoutedSessionsDoc](t, r.stdout, "prolexic.routed-sessions.v1")
	if strings.Join(doc.Customers, ",") != "example-a,example-b" {
		t.Errorf("customers = %v (in-use names, sorted)", doc.Customers)
	}
	if len(doc.Sessions) != 2 || doc.Sessions[0].DataCenter != "DC-A" || doc.Sessions[0].Customer != "example-a" {
		t.Errorf("sessions = %+v", doc.Sessions)
	}
	if doc.Failures == nil || len(doc.Failures) != 0 {
		t.Errorf("failures = %#v, want []", doc.Failures)
	}
}

func TestRoutedSessionsReportsFailedNames(t *testing.T) {
	api := newFakeAPI(t)
	api.routes["POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions"] = func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "example-bad") {
			w.WriteHeader(403)
			w.Write([]byte(`{"errorCode":"FORBIDDEN","message":"no access to example-bad"}`))
			return
		}
		w.Write([]byte(sessionsFixture))
	}

	r := runCLI(t, api.env(), "routed", "sessions", "--customer", "example-a,example-bad")
	if r.code != exitCode(apperr.Credentials) {
		t.Errorf("exit = %d, want 3 (the failures' common code)", r.code)
	}
	doc := decode[RoutedSessionsDoc](t, r.stdout, "prolexic.routed-sessions.v1")
	if len(doc.Sessions) != 2 || len(doc.Failures) != 1 || doc.Failures[0].Customer != "example-bad" {
		t.Errorf("doc = %+v", doc)
	}
	if !strings.Contains(r.stderr, "1 of 2 customer names failed") {
		t.Errorf("stderr = %s", r.stderr)
	}
}

func TestRoutedSessionsText(t *testing.T) {
	api := newFakeAPI(t)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 200, sessionsFixture)
	r := runCLI(t, api.env(), "routed", "sessions", "--customer", "example-a", "--format", "text")
	if r.code != 0 || !strings.Contains(r.stdout, "DC-A") || !strings.Contains(r.stdout, "2001:db8::2") {
		t.Errorf("exit %d, stdout:\n%s", r.code, r.stdout)
	}
}

func TestListFlagsTrimAndDropEmpty(t *testing.T) {
	var got []string
	f := pflag.NewFlagSet("t", pflag.ContinueOnError)
	listVar(f, &got, "customer", "")
	if err := f.Parse([]string{"--customer", "a, b,", "--customer", " c "}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "a|b|c" {
		t.Errorf("got %q", got)
	}
}

func TestReviewRound4Contracts(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /network-cloud-firewall/v2/aliases", 200, `[{"aliasId":101,"aliasName":"block-v4","aliasType":"SOURCE","accountId":"A-EXAMPLE","isCustomerEditable":true}]`)
	api.json("POST /prolexic-analytics/v2/metrics", 200, `{"status":true,"data":[{"service":"routed","metric":"bandwidthIn","points":[[1767400000,"NaN"],[1767400060,"Inf"],[1767400120,"5"]]}]}`)
	tests := []struct {
		name     string
		args     []string
		wantCode apperr.Kind
		wantErr  string
	}{
		{"help for an unknown topic", []string{"help", "bogus"}, apperr.Usage, "unknown help topic"},
		{"help for an unknown subcommand", []string{"help", "acl", "bogus"}, apperr.Usage, "unknown help topic"},
		{"empty --customer doesn't mean every name", []string{"attacks", "list", "--customer", "", "--since", "1h"}, apperr.Usage, "empty value"},
		{"comma-only --customer", []string{"routed", "sessions", "--customer", ","}, apperr.Usage, "empty value"},
		{"unknown customer name", []string{"attacks", "list", "--customer", "exmaple-a", "--since", "1h"}, apperr.NotFound, `unknown customer name "exmaple-a"`},
		{"dot version segment", []string{"aliases", "show", "--id", "101", "--version", ".."}, apperr.Usage, "can't be empty"},
		{"slash in version", []string{"aliases", "show", "--id", "101", "--version", "V1/../../x"}, apperr.Usage, "can't be empty"},
		{"dot target id", []string{"targets", "show", "--id", ".."}, apperr.Usage, "can't be empty"},
		{"NaN and Inf decode to 0", []string{"metrics", "--customer", "example-a", "--type", "routed:bandwidthIn", "--since", "1h"}, apperr.OK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runCLI(t, api.env(), tt.args...)
			if r.code != exitCode(tt.wantCode) || !strings.Contains(r.stderr, tt.wantErr) {
				t.Errorf("exit = %d (want %s), stderr = %s", r.code, tt.wantCode, r.stderr)
			}
		})
	}
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/..") || strings.Contains(c.Path, "attack-reports") || strings.Contains(c.Path, "/versions/") || strings.Contains(c.Path, "/targets/") {
			t.Errorf("request sent that should have been refused: %s %s", c.Method, c.Path)
		}
	}
}

// Every read command's client is read-only; only apply builds a write client.
func TestReadClientIsReadOnly(t *testing.T) {
	api := newFakeAPI(t)
	env := api.env()
	env.Home = t.TempDir()
	a := &app{env: env, section: "default"}
	c, err := a.readClient()
	if err != nil {
		t.Fatal(err)
	}
	err = c.Do(context.Background(), akamai.Request{Method: http.MethodPost, Path: "/network-cloud-firewall/v2/aliases"}, nil)
	if apperr.KindOf(err) != apperr.Bug || len(api.calls) != 0 {
		t.Errorf("err = %v, calls = %v", err, api.calls)
	}
}
