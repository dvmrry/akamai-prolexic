package akamai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
)

func testClient(t *testing.T, h http.HandlerFunc) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New(edgegrid.Credentials{
		Host: strings.TrimPrefix(srv.URL, "http://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at",
		AccountKey: "SWITCH",
	}, Options{Scheme: "http"})
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	return c, &waits
}

func TestDoDecodesAndSigns(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "EG1-HMAC-SHA256 ") {
			t.Errorf("unsigned request")
		}
		if r.URL.Query().Get("accountSwitchKey") != "SWITCH" || r.URL.Query().Get("a") != "1" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		w.Write([]byte(`{"name":"x","unexpected":true}`))
	})
	var out struct{ Name string }
	if err := c.Do(context.Background(), Request{Method: "GET", Path: "/p", Query: map[string][]string{"a": {"1"}}}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != "x" {
		t.Errorf("out = %+v", out)
	}
}

func TestGetRetriesHonouringRetryAfter(t *testing.T) {
	var n atomic.Int32
	c, waits := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
		case 2:
			w.WriteHeader(503)
		default:
			w.Write([]byte(`{}`))
		}
	})
	if err := c.Do(context.Background(), Request{Method: "GET", Path: "/p"}, nil); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 3 || len(*waits) != 2 || (*waits)[0] != 2*time.Second {
		t.Errorf("calls = %d, waits = %v", n.Load(), *waits)
	}
}

func TestGetGivesUpAfterMaxAttempts(t *testing.T) {
	var n atomic.Int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(502)
	})
	err := c.Do(context.Background(), Request{Method: "GET", Path: "/p"}, nil)
	if apperr.CodeOf(err) != apperr.Upstream || n.Load() != 4 {
		t.Errorf("err = %v after %d calls", err, n.Load())
	}
}

func TestPostIsNeverRetriedAndIsAmbiguousOn5xx(t *testing.T) {
	var n atomic.Int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(503)
	})
	err := c.Do(context.Background(), Request{Method: "POST", Path: "/p", JSON: map[string]int{"a": 1}}, nil)
	if n.Load() != 1 {
		t.Errorf("POST sent %d times", n.Load())
	}
	if !IsAmbiguous(err) {
		t.Errorf("err = %v, want ambiguous", err)
	}
}

func TestReadOnlyPostRetriesLikeAGet(t *testing.T) {
	var n atomic.Int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(504)
	})
	err := c.Do(context.Background(), Request{Method: "POST", Path: "/p", JSON: 1, ReadOnly: true}, nil)
	if n.Load() != 4 || IsAmbiguous(err) {
		t.Errorf("calls = %d, ambiguous = %v", n.Load(), IsAmbiguous(err))
	}
}

func TestPost4xxIsNotAmbiguous(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(400)
		w.Write([]byte(`{"errorCode":"INVALID_ENTRY","message":"bad entry","status":400}`))
	})
	err := c.Do(context.Background(), Request{Method: "POST", Path: "/p", JSON: 1}, nil)
	d := apperr.UpstreamOf(err)
	if IsAmbiguous(err) || d == nil || d.ErrorCode != "INVALID_ENTRY" || d.Detail != "bad entry" {
		t.Errorf("err = %v, detail = %+v", err, d)
	}
}

func TestProblemShapes(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantCode apperr.Code
		wantMsg  string
	}{
		{"gateway", 403, `{"type":"https://problems.luna.akamaiapis.net/-/pep-authz/deny","title":"Forbidden","detail":"The client does not have the grant needed","code":"403.0"}`, apperr.Credentials, "does not have the grant"},
		{"application", 404, `{"errorCode":"ALIAS_NOT_FOUND","message":"no alias 7"}`, apperr.NotFound, "no alias 7"},
		{"not json", 409, `<html>`, apperr.Conflict, "HTTP 409"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			})
			err := c.Do(context.Background(), Request{Method: "GET", Path: "/p"}, nil)
			if apperr.CodeOf(err) != tt.wantCode || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v (code %d)", err, apperr.CodeOf(err))
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter("Thu, 01 Jan 2026 00:00:05 GMT", now); !ok || d != 5*time.Second {
		t.Errorf("date form = %v %v", d, ok)
	}
	if _, ok := parseRetryAfter("soon", now); ok {
		t.Error("garbage accepted")
	}
}

func TestGatewayIncidentIDIsKept(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		w.Write([]byte(`{"type":"gateway","title":"Bad Gateway","incidentId":"incident-0001"}`))
	})
	c.MaxAttempts = 1
	err := c.Do(context.Background(), Request{Method: "GET", Path: "/p"}, nil)
	if d := apperr.UpstreamOf(err); d == nil || d.IncidentID != "incident-0001" {
		t.Errorf("detail = %+v", d)
	}
}

func TestResponseSizeCap(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, MaxResponseSize+1))
	})
	err := c.Do(context.Background(), Request{Method: "GET", Path: "/p"}, nil)
	if apperr.CodeOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

func TestDeadlineIsAnUpstreamFailure(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := c.Do(ctx, Request{Method: "GET", Path: "/p"}, nil)
	if apperr.CodeOf(err) != apperr.Upstream {
		t.Errorf("err = %v (code %d), want exit 5", err, apperr.CodeOf(err))
	}
}

func TestWriteWithUndecodableSuccessIsAmbiguous(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte(`{"version": `))
	})
	var out struct{ Version string }
	err := c.Do(context.Background(), Request{Method: "POST", Path: "/p", JSON: 1}, &out)
	if !IsAmbiguous(err) {
		t.Errorf("err = %v; a 2xx write took effect, so an unreadable body must be ambiguous", err)
	}
}
