package ncfapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
)

func serving(t *testing.T, body string) *V2 {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewV2(akamai.New(edgegrid.Credentials{Host: strings.TrimPrefix(srv.URL, "http://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at"}, akamai.Options{Scheme: "http"}))
}

// A version answer without an entries list is not an empty alias: read as
// one, it would hide every live entry.
func TestGetVersionNeedsAnEntriesList(t *testing.T) {
	for _, body := range []string{`{}`, `{"version":"V1","entries":null}`} {
		if _, err := serving(t, body).GetVersion(context.Background(), 101, "V1"); apperr.KindOf(err) != apperr.Upstream {
			t.Errorf("%s: err = %v, want an upstream error", body, err)
		}
	}
	v, err := serving(t, `{"version":"V1","entries":[]}`).GetVersion(context.Background(), 101, "V1")
	if err != nil || v.Entries == nil || len(v.Entries) != 0 {
		t.Errorf("a genuinely empty alias: %+v, %v", v, err)
	}
}
