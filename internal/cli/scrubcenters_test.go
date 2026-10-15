package cli

import (
	"strings"
	"testing"
)

func TestScrubCentersSortedAndLenient(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/scrub-centers", 200, `["lga3","ams3",{"x":1},"ams3",""]`)
	r := runCLI(t, api.env(), "scrub-centers")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s", r.code, r.stderr)
	}
	doc := decode[ScrubCentersDoc](t, r.stdout, "prolexic.scrub-centers.v1")
	if strings.Join(doc.ScrubCenters, ",") != "ams3,lga3" {
		t.Errorf("centers = %v", doc.ScrubCenters)
	}
	r = runCLI(t, api.env(), "scrub-centers", "--format", "text")
	if r.stdout != "ams3\nlga3\n" {
		t.Errorf("text = %q", r.stdout)
	}
}

func TestScrubCentersNoneIs404(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/scrub-centers", 404, `{"errorCode":"NOT_FOUND","message":"none"}`)
	r := runCLI(t, api.env(), "scrub-centers")
	doc := decode[ScrubCentersDoc](t, r.stdout, "prolexic.scrub-centers.v1")
	if r.code != 0 || doc.ScrubCenters == nil || len(doc.ScrubCenters) != 0 {
		t.Errorf("exit %d, doc %+v", r.code, doc)
	}
}
