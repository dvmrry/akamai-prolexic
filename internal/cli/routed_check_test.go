package cli

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const checkSessions = `[
  {"asn":64500,"dataCenter":"DC-A","routerName":"edge-1","customerBgpPeerIpv4":"192.0.2.14","customerBgpPeerIpv6":"2001:db8::e"},
  {"asn":64500,"dataCenter":"DC-B","routerName":"edge-2","customerBgpPeerIpv4":"192.0.2.6"}
]`

const (
	routesBoth = `[
  {"akamaiLocation":"L","dataCenter":"DC-A","routerName":"edge-1","prefix":"203.0.113.0/24","customerBgpPeerIp":"192.0.2.14","asPath":"64500"},
  {"akamaiLocation":"L","dataCenter":"DC-B","routerName":"edge-2","prefix":"203.0.113.0/24","customerBgpPeerIp":"192.0.2.6","asPath":"64500"}]`
	routesOne = `[
  {"akamaiLocation":"L","dataCenter":"DC-A","routerName":"edge-1","prefix":"203.0.113.0/24","customerBgpPeerIp":"192.0.2.14","asPath":"64500"}]`
)

func checkAPI(t *testing.T, routes func(attempt int) string) (*fakeAPI, *atomic.Int32) {
	api := newFakeAPI(t)
	var attempt atomic.Int32
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 200, checkSessions)
	api.routes["POST /prolexic-analytics/v2/routed/tunnel/routes"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(routes(int(attempt.Add(1)))))
	}
	return api, &attempt
}

// fakeClock makes env's waits instant and advances env.Now by them.
func fakeClock(env *Env) (slept *[]time.Duration) {
	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	slept = &[]time.Duration{}
	env.Sleep = func(_ context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		cur = cur.Add(d)
		return nil
	}
	env.Now = func() time.Time { return cur }
	return slept
}

func TestRoutedCheckPresentSatisfied(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesBoth })
	r := runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.9/24")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[RoutedCheckDoc](t, r.stdout, "prolexic.routed-check.v1")
	if !doc.Satisfied || doc.Attempts != 1 || doc.Prefix != "203.0.113.0/24" || doc.Expect != "present" || len(doc.Sessions) != 2 ||
		!doc.Sessions[0].Carried || doc.Sessions[0].DataCenter != "DC-A" || doc.Skipped == nil || doc.Sites == nil {
		t.Errorf("doc = %+v", doc)
	}
}

func TestRoutedCheckNotSatisfiedIsDrift(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesOne })
	r := runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24")
	if r.code != exitCode(apperr.Drift) || !strings.Contains(r.stderr, "1 of 2 sessions") {
		t.Errorf("exit = %d, stderr: %s", r.code, r.stderr)
	}
	doc := decode[RoutedCheckDoc](t, r.stdout, "prolexic.routed-check.v1")
	if doc.Satisfied || doc.Sessions[1].Carried {
		t.Errorf("doc = %+v", doc)
	}
}

func TestRoutedCheckAbsent(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return `[]` })
	r := runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--expect", "absent")
	if r.code != 0 {
		t.Errorf("absent, nothing carried: exit = %d: %s", r.code, r.stderr)
	}
	api, _ = checkAPI(t, func(int) string { return routesOne })
	r = runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--expect", "absent")
	if r.code != exitCode(apperr.Drift) {
		t.Errorf("absent, still carried: exit = %d", r.code)
	}
}

func TestRoutedCheckSiteAndFamily(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesOne })
	r := runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--site", "DC-A")
	if r.code != 0 {
		t.Errorf("site DC-A: exit = %d: %s", r.code, r.stderr)
	}
	// v6: edge-2 has no v6 peer, so it is skipped rather than expected; the
	// route list has no v6 route, so the one expected session is off.
	r = runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "2001:db8:1::/48")
	doc := decode[RoutedCheckDoc](t, r.stdout, "prolexic.routed-check.v1")
	if r.code != exitCode(apperr.Drift) || len(doc.Sessions) != 1 || len(doc.Skipped) != 1 || doc.Skipped[0].RouterName != "edge-2" {
		t.Errorf("exit = %d, doc = %+v", r.code, doc)
	}
}

func TestRoutedCheckNoExpectedSessionsIsNotFound(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesBoth })
	r := runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--site", "DC-NOWHERE")
	if r.code != exitCode(apperr.NotFound) {
		t.Errorf("exit = %d, want 4: %s", r.code, r.stderr)
	}
}

func TestRoutedCheckUsageErrors(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesBoth })
	for _, args := range [][]string{
		{"routed", "check"},
		{"routed", "check", "--prefix", "nope"},
		{"routed", "check", "--prefix", "203.0.113.0/24", "--expect", "maybe"},
		{"routed", "check", "--prefix", "203.0.113.0/24", "--wait", "1m", "--interval", "0s"},
	} {
		if r := runCLI(t, api.env(), args...); r.code != exitCode(apperr.Usage) {
			t.Errorf("%v: exit = %d, want 2", args, r.code)
		}
	}
}

func TestRoutedCheckWaitPollsUntilSatisfied(t *testing.T) {
	api, attempts := checkAPI(t, func(n int) string {
		if n < 3 {
			return routesOne
		}
		return routesBoth
	})
	env := api.env()
	slept := fakeClock(&env)
	r := runCLI(t, env, "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--wait", "5m", "--interval", "30s")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[RoutedCheckDoc](t, r.stdout, "prolexic.routed-check.v1")
	if !doc.Satisfied || doc.Attempts != 3 || attempts.Load() != 3 || len(*slept) != 2 || (*slept)[0] != 30*time.Second {
		t.Errorf("attempts = %d (%d fetches), slept = %v, doc = %+v", doc.Attempts, attempts.Load(), *slept, doc)
	}
	if n := strings.Count(r.stderr, "prolexic: attempt "); n != 2 || !strings.Contains(r.stderr, "checking again in 30s") {
		t.Errorf("progress (%d attempt lines):\n%s", n, r.stderr)
	}
}

func TestRoutedCheckWaitTimesOut(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesOne })
	env := api.env()
	slept := fakeClock(&env)
	r := runCLI(t, env, "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--wait", "70s", "--interval", "30s")
	doc := decode[RoutedCheckDoc](t, r.stdout, "prolexic.routed-check.v1")
	// Attempts at 0s, 30s, 60s and 70s: the last sleep is clipped to the deadline.
	if r.code != exitCode(apperr.Drift) || doc.Attempts != 4 || len(*slept) != 3 || (*slept)[2] != 10*time.Second {
		t.Errorf("exit = %d, attempts = %d, slept = %v", r.code, doc.Attempts, *slept)
	}
}

func TestRoutedCheckHonoursCancellation(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesOne })
	ctx, cancel := context.WithCancel(context.Background())
	env := api.env()
	env.Sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	env.Stdout, env.Stderr = &strings.Builder{}, &strings.Builder{}
	env.Home = t.TempDir()
	code := Run(ctx, []string{"routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--wait", "5m"}, env)
	if code == 0 || code == exitCode(apperr.Drift) {
		t.Errorf("exit = %d, want a cancellation error", code)
	}
}

func TestRoutedCheckFailedNameIsNotSatisfied(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesBoth })
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 403, `{"errorCode":"FORBIDDEN","message":"no access"}`)
	r := runCLI(t, api.env(), "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--expect", "absent")
	if r.code != exitCode(apperr.Credentials) {
		t.Errorf("exit = %d, want 3", r.code)
	}
}

// A name failing both queries keeps the exit code it had before failures
// became document data: the sessions failure decides it.
func TestRoutedCheckSessionsFailureDecidesTheExit(t *testing.T) {
	api, _ := checkAPI(t, func(int) string { return routesBoth })
	api.json("POST /prolexic-analytics/v2/routed/tunnel/bgp-sessions", 403, `{"errorCode":"FORBIDDEN","message":"no access"}`)
	api.json("POST /prolexic-analytics/v2/routed/tunnel/routes", 404, `{"title":"Not Found","status":404}`)
	env := api.env()
	fakeClock(&env)
	r := runCLI(t, env, "routed", "check", "--customer", "example-a", "--prefix", "203.0.113.0/24", "--expect", "absent", "--wait", "1m", "--interval", "30s")
	if r.code != exitCode(apperr.Credentials) {
		t.Errorf("exit = %d, want 3 (credentials): %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, ", 1 failed names;") {
		t.Errorf("a name failing both queries counted twice:\n%s", r.stderr)
	}
}
