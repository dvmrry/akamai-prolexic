package ncfapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
)

func TestDeploymentReportsTheNewestFailedRuleset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ruleSets":[
		  {"deploymentStatus":"FAILED","version":5,"rulesDeployStats":{"failed":0}},
		  {"deploymentStatus":"PRODUCTION","version":7,"rulesDeployStats":{"failed":0}},
		  {"deploymentStatus":"FAILED","version":8,"rulesDeployStats":{"failed":0}}]}`))
	}))
	defer srv.Close()
	c := akamai.New(edgegrid.Credentials{Host: strings.TrimPrefix(srv.URL, "http://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at"}, akamai.Options{Scheme: "http"})
	d, err := deployment(context.Background(), c, v2Path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != 7 || d.State != "PRODUCTION" || d.FailedVersion != 8 || d.Failure() == "" {
		t.Errorf("deployment = %+v, failure %q", d, d.Failure())
	}
}
