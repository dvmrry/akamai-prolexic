package cli

import (
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

func liveAPI(t *testing.T) *fakeAPI {
	api := newFakeAPI(t)
	api.json("GET /network-cloud-firewall/v2/aliases", 200, `[]`)
	api.json("GET /prolexic-network-health/v1/targets", 200, `{"targets":[]}`)
	return api
}

func TestDoctorLiveAllOK(t *testing.T) {
	api := liveAPI(t)
	r := runCLI(t, api.env(), "doctor", "--live")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[DoctorDoc](t, r.stdout, "prolexic.doctor.v1")
	if len(doc.APIs) != 3 {
		t.Fatalf("apis = %+v", doc.APIs)
	}
	for i, want := range []string{"ncf", "analytics", "networkHealth"} {
		if s := doc.APIs[i]; s.API != want || !s.OK || s.Kind != "" {
			t.Errorf("apis[%d] = %+v", i, s)
		}
	}
	if len(api.calls) != 3 {
		t.Errorf("calls = %+v, want one per API", api.calls)
	}
	if strings.Contains(r.stdout, strings.TrimPrefix(api.srv.URL, "http://")) {
		t.Errorf("doctor leaked the host: %s", r.stdout)
	}
}

func TestDoctorLiveReportsOnlyTheFailedAPI(t *testing.T) {
	api := liveAPI(t)
	api.json("GET /prolexic-analytics/v2/customer/names", 403, `{"type":"forbidden","title":"Forbidden","detail":"no grant"}`)
	r := runCLI(t, api.env(), "doctor", "--live")
	if r.code != exitCode(apperr.Credentials) {
		t.Fatalf("exit = %d, want 3: %s", r.code, r.stderr)
	}
	doc := decode[DoctorDoc](t, r.stdout, "prolexic.doctor.v1")
	var failed []APIStatus
	for _, s := range doc.APIs {
		if !s.OK {
			failed = append(failed, s)
		}
	}
	if len(doc.APIs) != 3 || len(failed) != 1 || failed[0].API != "analytics" {
		t.Fatalf("apis = %+v", doc.APIs)
	}
	if failed[0].Kind != "credentials" || !strings.Contains(failed[0].Message, "ask for Analytics read access") {
		t.Errorf("failure = %+v", failed[0])
	}
	if !strings.Contains(r.stderr, "analytics") {
		t.Errorf("stderr = %s", r.stderr)
	}

	r = runCLI(t, api.env(), "doctor", "--live", "--format", "text")
	if !strings.Contains(r.stdout, "analytics") || !strings.Contains(r.stdout, "FAILED (credentials)") || !strings.Contains(r.stdout, "ncf") {
		t.Errorf("text = %s", r.stdout)
	}
}

func TestDoctorLiveMixedKindsIsUpstream(t *testing.T) {
	api := liveAPI(t)
	api.json("GET /prolexic-analytics/v2/customer/names", 403, `{"detail":"no grant"}`)
	api.json("GET /prolexic-network-health/v1/targets", 400, `{"detail":"bad"}`)
	r := runCLI(t, api.env(), "doctor", "--live")
	if r.code != exitCode(apperr.Upstream) {
		t.Errorf("exit = %d, want upstream: %s", r.code, r.stderr)
	}
}

func TestDoctorWithoutLiveMakesNoRequests(t *testing.T) {
	api := liveAPI(t)
	r := runCLI(t, api.env(), "doctor")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	if len(api.calls) != 0 {
		t.Errorf("calls = %+v, want none", api.calls)
	}
	if doc := decode[DoctorDoc](t, r.stdout, "prolexic.doctor.v1"); doc.APIs != nil {
		t.Errorf("apis = %+v", doc.APIs)
	}
}

func TestDoctorLiveSkippedWithoutReadCredentials(t *testing.T) {
	api := liveAPI(t)
	r := runCLI(t, Env{}, "doctor", "--live")
	if r.code != exitCode(apperr.Credentials) {
		t.Errorf("exit = %d, want 3", r.code)
	}
	if doc := decode[DoctorDoc](t, r.stdout, "prolexic.doctor.v1"); doc.APIs != nil {
		t.Errorf("apis = %+v", doc.APIs)
	}
	if len(api.calls) != 0 {
		t.Errorf("calls = %+v", api.calls)
	}
}
