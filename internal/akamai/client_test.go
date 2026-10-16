package akamai

import (
	"context"
	"crypto/x509"
	"errors"
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
	if apperr.KindOf(err) != apperr.Upstream || n.Load() != 4 {
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
		wantCode apperr.Kind
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
			if apperr.KindOf(err) != tt.wantCode || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v (kind %s)", err, apperr.KindOf(err))
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d, ok := parseRetryAfter("Thu, 01 Jan 2026 00:00:05 GMT", now, time.Minute); !ok || d != 5*time.Second {
		t.Errorf("date form = %v %v", d, ok)
	}
	if _, ok := parseRetryAfter("soon", now, time.Minute); ok {
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
	if apperr.KindOf(err) != apperr.Upstream || !strings.Contains(err.Error(), "larger than") {
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
	if apperr.KindOf(err) != apperr.Upstream {
		t.Errorf("err = %v (kind %s), want upstream", err, apperr.KindOf(err))
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

func TestAnalyticsErrorPathsAreSurfaced(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"status":400,"errorCode":"ILLEGAL_ARGUMENT","data":"","args":["x"],
		  "errorPaths":[{"path":"metrics[0].subnet","message":"is required for fbm metrics"}]}`))
	})
	err := c.Do(context.Background(), Request{Method: "GET", Path: "/p"}, nil)
	if !strings.Contains(err.Error(), "metrics[0].subnet: is required for fbm metrics") {
		t.Errorf("err = %v", err)
	}
}

func TestUncleanPathsAreRefused(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Errorf("sent %s", r.URL.Path) })
	for _, p := range []string{"/a/../b", "/a/./b", "/a//b", "/a/", "a"} {
		if err := c.Do(context.Background(), Request{Method: "GET", Path: p}, nil); apperr.KindOf(err) != apperr.Usage {
			t.Errorf("%q: err = %v, want a usage error", p, err)
		}
	}
}

func TestRetryAfterIsClampedNotOverflowed(t *testing.T) {
	d, ok := parseRetryAfter("99999999999999", time.Now(), 30*time.Second)
	if !ok || d != 30*time.Second {
		t.Errorf("d = %v", d)
	}
}

func TestReadOnlyClientRefusesWritesBeforeSending(t *testing.T) {
	sent := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { sent++; w.Write([]byte(`{}`)) })
	c.readOnly = true
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if err := c.Do(context.Background(), Request{Method: m, Path: "/x"}, nil); apperr.KindOf(err) != apperr.Bug {
			t.Errorf("%s: err = %v, want a refusal (bug)", m, err)
		}
	}
	if sent != 0 {
		t.Fatalf("%d writes reached the server", sent)
	}
	for _, req := range []Request{{Method: http.MethodGet, Path: "/x"}, {Method: http.MethodPost, Path: "/q", ReadOnly: true}} {
		if err := c.Do(context.Background(), req, nil); err != nil {
			t.Errorf("%s %s: a read was refused: %v", req.Method, req.Path, err)
		}
	}
}

// A 2xx that isn't the API's answer never passes as one.
func TestNonAnswersAreErrors(t *testing.T) {
	for name, tt := range map[string]struct {
		ctype, body string
		method      string
		allowEmpty  bool
		wantErr     bool
		ambiguous   bool
	}{
		"html page on a read":   {"text/html", "<html>login</html>", http.MethodGet, false, true, false},
		"html without the type": {"", "<!doctype html>", http.MethodGet, false, true, false},
		"html page on a write":  {"text/html", "<html>login</html>", http.MethodPatch, false, true, true},
		"empty body on a read":  {"application/json", "", http.MethodGet, false, true, false},
		"null on a read":        {"application/json", "null", http.MethodGet, false, true, false},
		"empty, allowed":        {"application/json", "", http.MethodGet, true, false, false},
		"a real answer":         {"application/json", `{"x":1}`, http.MethodGet, false, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if tt.ctype != "" {
					w.Header().Set("Content-Type", tt.ctype)
				}
				w.Write([]byte(tt.body))
			})
			var out map[string]any
			err := c.Do(context.Background(), Request{Method: tt.method, Path: "/x", AllowEmpty: tt.allowEmpty}, &out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if u := apperr.UpstreamOf(err); err != nil && (u == nil || u.Ambiguous != tt.ambiguous) {
				t.Errorf("upstream = %+v, want ambiguous %v", u, tt.ambiguous)
			}
		})
	}
}

// A stalled body is cut off by the attempt deadline instead of hanging.
func TestAStalledResponseTimesOut(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"x":`))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	c.AttemptTimeout, c.MaxAttempts = 50*time.Millisecond, 1
	start := time.Now()
	err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"}, &map[string]any{})
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

// A transport error never prints the URL: the host embeds a token, and the
// query carries the account switch key.
func TestTransportErrorsHideTheURL(t *testing.T) {
	c := New(edgegrid.Credentials{Host: "akab-host-token.example.invalid", ClientToken: "ct", ClientSecret: "cs", AccessToken: "at", AccountKey: "SWITCH-KEY"}, Options{Scheme: "http"})
	c.MaxAttempts = 1
	err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"}, nil)
	if err == nil || strings.Contains(err.Error(), "akab-host-token") || strings.Contains(err.Error(), "SWITCH-KEY") {
		t.Errorf("err = %v", err)
	}
}

func TestProxyAuthIsNotRetried(t *testing.T) {
	if !proxyAuth(errors.New("Proxy Authentication Required")) || proxyAuth(errors.New("connection refused")) {
		t.Error("a 407 from the proxy must not be retried; other transport errors may be")
	}
}

// A declared CA bundle makes a server signed by that CA trusted (the case of
// a TLS-inspecting proxy); without it the same server is refused.
func TestRootCAsTrustADeclaredCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	creds := edgegrid.Credentials{Host: strings.TrimPrefix(srv.URL, "https://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at"}

	plain := New(creds, Options{})
	plain.MaxAttempts = 1
	if err := plain.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"}, &map[string]any{}); err == nil {
		t.Fatal("an unknown CA was trusted without a bundle")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	trusted := New(creds, Options{RootCAs: pool})
	if err := trusted.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"}, &map[string]any{}); err != nil {
		t.Errorf("with the CA declared: %v", err)
	}
}
