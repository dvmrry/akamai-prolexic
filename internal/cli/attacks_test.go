package cli

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

var fixedNow = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

const attacksFixture = `{"currentContract":"example-a","status":true,"statusMsg":"ok","data":[
  {"attackId":902,"eventId":7,"startTime":1767400000,"eventStartTime":1767400000,"eventStartTimeAsString":"2026-01-03 00:26:40","eventEndTimeAsString":"","eventTypes":["SYN Flood"],
   "destinations":[{"ip":"203.0.113.10","netmask":32}],"destinationPort":null,"peaks":[{"location":"LOC-A","peakId":1,"bandwidth":900,"pps":90}]},
  {"attackId":901,"eventId":6,"startTime":1767300000,"endTime":1767301000,"eventStartTime":1767300000,"eventStartTimeAsString":"2026-01-01 20:40:00","eventEndTimeAsString":"2026-01-01 20:56:40","eventTypes":["UDP Flood","ICMP Flood"],
   "destinations":[{"ip":"2001:db8::10","netmask":128}],"unknownField":1}
]}`

func TestAttacksListWindowAndSort(t *testing.T) {
	api := newFakeAPI(t)
	start, end := fixedNow.Add(-24*time.Hour).Unix(), fixedNow.Unix()
	api.json(fmt.Sprintf("GET /prolexic-analytics/v2/attack-reports/contract/example-a/start/%d/end/%d", start, end), 200, attacksFixture)
	env := api.env()
	env.Now = func() time.Time { return fixedNow }

	r := runCLI(t, env, "attacks", "list", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if doc.Start != "2026-01-01T00:00:00Z" || doc.End != "2026-01-02T00:00:00Z" {
		t.Errorf("window = %s .. %s", doc.Start, doc.End)
	}
	if len(doc.Attacks) != 2 || doc.Attacks[0].AttackID != 901 || doc.Attacks[0].Customer != "example-a" || doc.Attacks[1].EndTime != 0 {
		t.Errorf("attacks = %+v", doc.Attacks)
	}

	r = runCLI(t, env, "attacks", "list", "--customer", "example-a", "--format", "text")
	if !strings.Contains(r.stdout, "ongoing") || !strings.Contains(r.stdout, "2001:db8::10/128") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestAttacksListExplicitWindowAndEscaping(t *testing.T) {
	api := newFakeAPI(t)
	var path string
	api.routes["GET /prolexic-analytics/v2/attack-reports/contract/example a/start/1767225600/end/1767229200"] = func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		w.Write([]byte(`{"status":true,"data":[]}`))
	}
	env := api.env()
	env.Now = func() time.Time { return fixedNow }
	r := runCLI(t, env, "attacks", "list", "--customer", "example a", "--start", "2026-01-01T00:00:00Z", "--end", "2026-01-01T01:00:00Z")
	if r.code != 0 || !strings.HasSuffix(path, "/contract/example%20a/start/1767225600/end/1767229200") {
		t.Errorf("exit %d, escaped path %q, stderr %s", r.code, path, r.stderr)
	}
	doc := decode[ops.AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if doc.Attacks == nil || len(doc.Attacks) != 0 {
		t.Errorf("attacks = %#v, want []", doc.Attacks)
	}
}

func TestAttacksListUsageErrors(t *testing.T) {
	api := newFakeAPI(t)
	for _, args := range [][]string{
		{"--since", "1h", "--start", "2026-01-01T00:00:00Z"},
		{"--since", "1h", "--end", "2026-01-01T00:00:00Z"},
		{"--end", "2026-01-01T00:00:00Z"},
		{"--start", "yesterday"},
		{"--start", "2026-01-02T00:00:00Z", "--end", "2026-01-01T00:00:00Z"},
		{"--since", "0s"},
		{"--since", "-1h"},
	} {
		r := runCLI(t, api.env(), append([]string{"attacks", "list", "--customer", "example-a"}, args...)...)
		if r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
	}
}

func TestAttacksListSurfacesInvalidSpanPerCustomer(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/attack-reports/contract/example-a/start/1704067200/end/1767312000", 400,
		`{"errorCode":"INVALID_START_END","message":"invalid start/end"}`)
	r := runCLI(t, api.env(), "attacks", "list", "--customer", "example-a", "--start", "2024-01-01T00:00:00Z", "--end", "2026-01-02T00:00:00Z")
	if r.code == 0 {
		t.Fatalf("exit = 0")
	}
	doc := decode[ops.AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if len(doc.Failures) != 1 || !strings.Contains(doc.Failures[0].Message, "invalid start/end") {
		t.Errorf("failures = %+v", doc.Failures)
	}
}

func TestAttacksListEnvelopeFailure(t *testing.T) {
	api := newFakeAPI(t)
	api.routes["GET /prolexic-analytics/v2/attack-reports/contract/example-a/start/1767225600/end/1767312000"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":false,"statusMsg":"range too long","data":[]}`))
	}
	env := api.env()
	env.Now = func() time.Time { return fixedNow }
	r := runCLI(t, env, "attacks", "list", "--customer", "example-a")
	doc := decode[ops.AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if r.code != exitCode(apperr.Upstream) || len(doc.Failures) != 1 || !strings.Contains(doc.Failures[0].Message, "range too long") {
		t.Errorf("exit %d, doc %+v", r.code, doc)
	}
}

const attackFixture = `{"currentContract":"example-a","status":true,"statusMsg":"ok","data":[
  {"attackId":901,"attackTypeName":"SYN Flood","destinationPort":"443","startTime":1767300000,"eventId":6,"eventBw":900,"eventPps":90,"ip":"203.0.113.10","location":"LOC-B","netmask":32,"eventPeakId":2},
  {"attackId":901,"attackTypeName":"SYN Flood","startTime":1767300000,"endTime":1767301000,"eventId":6,"eventBw":800,"eventPps":80,"ip":"203.0.113.10","location":"LOC-A","netmask":32,"eventPeakId":1}
]}`

func TestAttacksShow(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/attack-report/contract/example-a/attack-id/901", 200, attackFixture)
	r := runCLI(t, api.env(), "attacks", "show", "--id", "901", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.AttackDoc](t, r.stdout, "prolexic.attack.v1")
	if doc.AttackID != 901 || len(doc.Rows) != 2 || doc.Rows[0].Location != "LOC-A" || doc.Rows[1].EventBw != 900 {
		t.Errorf("doc = %+v", doc)
	}

	for _, args := range [][]string{{"--id", "901"}, {"--customer", "example-a"}} {
		if r := runCLI(t, api.env(), append([]string{"attacks", "show"}, args...)...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
	}

	api.json("GET /prolexic-analytics/v2/attack-report/contract/example-a/attack-id/5", 200, `{"status":true,"data":[]}`)
	if r := runCLI(t, api.env(), "attacks", "show", "--id", "5", "--customer", "example-a"); r.code != exitCode(apperr.NotFound) {
		t.Errorf("empty report: exit = %d, want 4", r.code)
	}
}

func TestAttacksLenientEpochs(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/attack-reports/contract/example-a/start/1767225600/end/1767312000", 200,
		`{"status":true,"data":[{"attackId":1,"startTime":"1767300000000","endTime":"1767301000","eventStartTime":1767300000000,"eventTypes":[]}]}`)
	api.json("GET /prolexic-analytics/v2/attack-report/contract/example-a/attack-id/1", 200,
		`{"status":true,"data":[{"attackId":1,"location":"LOC-A","ip":"203.0.113.10","netmask":32,"startTime":"1767300000000","endTime":null}]}`)
	env := api.env()
	env.Now = func() time.Time { return fixedNow }
	r := runCLI(t, env, "attacks", "list", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("list exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ops.AttacksDoc](t, r.stdout, "prolexic.attacks.v1")
	if a := doc.Attacks[0]; a.StartTime != 1767300000 || a.EndTime != 1767301000 || a.EventStartTime != 1767300000 {
		t.Errorf("attack = %+v", a)
	}
	r = runCLI(t, env, "attacks", "show", "--id", "1", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("show exit = %d: %s", r.code, r.stderr)
	}
	one := decode[ops.AttackDoc](t, r.stdout, "prolexic.attack.v1")
	if one.Rows[0].StartTime != 1767300000 || one.Rows[0].EndTime != 0 {
		t.Errorf("row = %+v", one.Rows[0])
	}
}
