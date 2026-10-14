package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const criticalFixture = `{"currentContract":"example-a","status":true,"statusMsg":"ok","data":[
  {"eventId":"11","summary":"Tunnel down","location":"LOC-A","firstOccur":1767300000,"recentOccur":1767310000,"count":3}
]}`

const eventsFixture = `{"currentContract":"example-a","status":true,"statusMsg":"ok","data":[
  {"eventTitle":"SYN flood","eventType":"attack","service":"Mitigation","severity":3,"isOngoing":true,"eventStartTime":1767305000,
   "eventInfo":{"location":"LOC-A","endTime":false,"topSourceIPs":[{"198.51.100.7":{"bps":"10","pps":"1","flows":"2"}}]}},
  {"eventTitle":"old alert","eventType":"alert","service":"bgp","isOngoing":false,"eventStartTime":1760000000,"eventEndTime":1760000100}
]}`

func eventsAPI(t *testing.T) *fakeAPI {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/critical-events/contract/example-a", 200, criticalFixture)
	api.json("GET /prolexic-analytics/v2/events/contract/example-a", 200, eventsFixture)
	return api
}

func TestEventsMergesAndSorts(t *testing.T) {
	api := eventsAPI(t)
	r := runCLI(t, api.env(), "events", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[EventsDoc](t, r.stdout, "prolexic.events.v1")
	var got []string
	for _, e := range doc.Events {
		got = append(got, e.Kind)
	}
	// Sorted by time: old alert, ongoing attack, then the critical event.
	if strings.Join(got, " ") != "event event critical" || doc.Events[0].Event.EventTitle != "old alert" ||
		doc.Events[1].Event.EventInfo.Location != "LOC-A" || doc.Events[2].Time != "2026-01-01T23:26:40Z" {
		t.Errorf("events = %v", got)
	}
	if doc.Start != "" || doc.End != "" {
		t.Errorf("no window asked for, got %s .. %s", doc.Start, doc.End)
	}
}

func TestEventsCriticalOnlyAndWindow(t *testing.T) {
	api := eventsAPI(t)
	env := api.env()
	env.Now = func() time.Time { return time.Unix(1767320000, 0) }

	r := runCLI(t, env, "events", "--customer", "example-a", "--critical-only")
	doc := decode[EventsDoc](t, r.stdout, "prolexic.events.v1")
	if len(doc.Events) != 1 || doc.Events[0].Kind != "critical" || doc.Events[0].Critical.Summary != "Tunnel down" {
		t.Errorf("events = %+v", doc.Events)
	}
	for _, c := range api.calls {
		if strings.Contains(c.Path, "/events/") && !strings.Contains(c.Path, "critical") {
			t.Errorf("--critical-only called %s", c.Path)
		}
	}

	// A 3h window ending at 1767320000 drops the old alert but keeps the
	// ongoing attack (its span is open-ended) and the critical event.
	r = runCLI(t, env, "events", "--customer", "example-a", "--since", "3h")
	doc = decode[EventsDoc](t, r.stdout, "prolexic.events.v1")
	if len(doc.Events) != 2 || doc.Start == "" {
		t.Errorf("windowed events = %+v", doc.Events)
	}
}

func TestEventsOneListFailingFailsTheName(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/critical-events/contract/example-a", 200, criticalFixture)
	api.json("GET /prolexic-analytics/v2/events/contract/example-a", 403, `{"errorCode":"FORBIDDEN","message":"no access"}`)
	r := runCLI(t, api.env(), "events", "--customer", "example-a")
	doc := decode[EventsDoc](t, r.stdout, "prolexic.events.v1")
	if r.code != int(apperr.Credentials) || len(doc.Failures) != 1 || len(doc.Events) != 0 {
		t.Errorf("exit %d, doc %+v", r.code, doc)
	}
}

func TestEventsUsage(t *testing.T) {
	api := eventsAPI(t)
	r := runCLI(t, api.env(), "events", "--customer", "example-a", "--since", "1h", "--start", "2026-01-01T00:00:00Z")
	if r.code != int(apperr.Usage) {
		t.Errorf("exit = %d, want 2", r.code)
	}
}

// Live sends lastOccurred as a string of epoch milliseconds, and the spec's
// other epochs may drift the same way.
func TestEventsLenientEpochs(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/critical-events/contract/example-a", 200,
		`{"status":true,"data":[{"eventId":"11","firstOccur":"1767300000000","recentOccur":"1767310000"}]}`)
	api.json("GET /prolexic-analytics/v2/events/contract/example-a", 200,
		`{"status":true,"data":[{"eventTitle":"SYN flood","eventType":"attack","isOngoing":false,"eventStartTime":"1767305000000","eventEndTime":1767306000000,
		   "eventInfo":{"startTime":"1767305000000","lastOccurred":"1700000000000","endTime":false}}]}`)
	r := runCLI(t, api.env(), "events", "--customer", "example-a")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[EventsDoc](t, r.stdout, "prolexic.events.v1")
	if len(doc.Events) != 2 {
		t.Fatalf("events = %+v", doc.Events)
	}
	ev := doc.Events[0].Event
	if ev == nil || ev.EventStartTime != 1767305000 || ev.EventEndTime != 1767306000 || ev.EventInfo.LastOccurred != 1700000000 {
		t.Errorf("event = %+v", ev)
	}
	if c := doc.Events[1].Critical; c == nil || c.FirstOccur != 1767300000 || c.RecentOccur != 1767310000 {
		t.Errorf("critical = %+v", c)
	}
}

func TestEventsGarbageEpochIsADecodeError(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/critical-events/contract/example-a", 200, `{"status":true,"data":[]}`)
	api.json("GET /prolexic-analytics/v2/events/contract/example-a", 200,
		`{"status":true,"data":[{"eventType":"alert","eventStartTime":"soon"}]}`)
	r := runCLI(t, api.env(), "events", "--customer", "example-a")
	if r.code != int(apperr.Upstream) {
		t.Errorf("exit = %d, want 5", r.code)
	}
}
