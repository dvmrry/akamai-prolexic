package networkhealth

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

func TestTargetIDIsAPathSegment(t *testing.T) {
	sent := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent++ }))
	t.Cleanup(srv.Close)
	c := New(akamai.New(edgegrid.Credentials{
		Host: strings.TrimPrefix(srv.URL, "http://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at",
	}, akamai.Options{Scheme: "http"}))
	for _, bad := range []string{"", ".", "..", "a/b"} {
		if _, err := c.Target(context.Background(), bad); apperr.KindOf(err) != apperr.Usage {
			t.Errorf("Target(%q) = %v, want a usage error", bad, err)
		}
	}
	if sent != 0 {
		t.Errorf("%d requests sent, want none", sent)
	}
}
