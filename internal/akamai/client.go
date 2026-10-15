// Package akamai is the HTTP transport shared by every API this CLI calls:
// EdgeGrid signing, JSON in and out, lenient decoding, error classification
// and the retry policy.
//
// Retry policy: only reads are retried (GETs, and the POSTs that only query,
// marked Request.ReadOnly), on 429/502/503/504 or a transport
// error, honouring Retry-After, with exponential backoff and full jitter. A
// write is sent exactly once; if it fails in a way that may have taken
// effect, the error is marked Ambiguous and the caller must prove the outcome
// by reading state, never by retrying.
package akamai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/version"
)

// MaxResponseSize bounds a response body. The largest expected one is an
// alias list or a 19,999-entry BIG alias, far below it.
const MaxResponseSize = 16 << 20

// Client calls one Akamai API host with one set of credentials.
type Client struct {
	base       url.URL
	accountKey string
	http       *http.Client
	userAgent  string

	MaxAttempts int           // for GETs; 1 disables retries
	BaseDelay   time.Duration // first backoff step
	MaxDelay    time.Duration // cap on any single wait, Retry-After included
	sleep       func(context.Context, time.Duration) error
}

// Options tune a Client. The zero value is production behaviour.
type Options struct {
	// Base is the transport under the signer; nil means a clone of
	// http.DefaultTransport, which honours HTTPS_PROXY and the system roots
	// (so a TLS-inspecting proxy works once its CA is trusted).
	Base http.RoundTripper
	// Scheme overrides "https", for tests against a plain httptest server.
	Scheme string
}

// New returns a client for creds.
func New(creds edgegrid.Credentials, opts Options) *Client {
	base := opts.Base
	if base == nil {
		base = http.DefaultTransport.(*http.Transport).Clone()
	}
	scheme := opts.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return &Client{
		base:        url.URL{Scheme: scheme, Host: creds.Host},
		accountKey:  creds.AccountKey,
		http:        &http.Client{Transport: &edgegrid.Transport{Signer: edgegrid.NewSigner(creds), Base: base}},
		userAgent:   "prolexic/" + version.Current().Version,
		MaxAttempts: 4,
		BaseDelay:   500 * time.Millisecond,
		MaxDelay:    30 * time.Second,
		sleep:       sleepCtx,
	}
}

// Request is one API call. Path is absolute from the host
// ("/network-cloud-firewall/v1/acls/aliases").
type Request struct {
	Method string
	Path   string
	Query  url.Values
	// JSON, when non-nil, is marshalled as the body.
	JSON any
	// Body and ContentType send a raw body instead (e.g. multipart). Body
	// must be fully buffered: it is signed and may be re-read.
	Body        []byte
	ContentType string
	// ReadOnly marks a non-GET that only queries (the Analytics routed
	// endpoints are POSTs): it is retried like a GET and never ambiguous.
	ReadOnly bool
}

// safe reports whether req may be retried: it changes nothing upstream.
func (r Request) safe() bool { return r.Method == http.MethodGet || r.ReadOnly }

// Do sends req and decodes a 2xx JSON response into out (if non-nil).
// Unknown response fields are ignored: the live APIs don't match their specs.
func (c *Client) Do(ctx context.Context, req Request, out any) error {
	// A value that slipped into the path as "", "." or ".." would change which
	// endpoint is called; refuse anything that isn't already a clean path.
	if p := path.Clean(req.Path); p != req.Path || !strings.HasPrefix(req.Path, "/") {
		return apperr.New(apperr.Usage, "%s %q: a value can't be an empty, . or .. path segment", req.Method, req.Path)
	}
	body, contentType := req.Body, req.ContentType
	if req.JSON != nil {
		b, err := json.Marshal(req.JSON)
		if err != nil {
			return fmt.Errorf("encode %s %s: %w", req.Method, req.Path, err)
		}
		body, contentType = b, "application/json"
	}

	u := c.base
	u.Path = req.Path
	q := url.Values{}
	for k, v := range req.Query {
		q[k] = v
	}
	if c.accountKey != "" {
		q.Set("accountSwitchKey", c.accountKey)
	}
	u.RawQuery = q.Encode()

	safe := req.safe()
	attempts := 1
	if safe {
		attempts = max(c.MaxAttempts, 1)
	}
	for attempt := 1; ; attempt++ {
		resp, err := c.send(ctx, req.Method, u.String(), body, contentType)
		if err != nil {
			// A cancelled GET is just cancelled; a cancelled write may already
			// have landed, so it falls through and is marked ambiguous.
			if ctx.Err() != nil && safe {
				return ctx.Err()
			}
			if ctx.Err() == nil && attempt < attempts {
				if err := c.sleep(ctx, c.backoff(attempt, "")); err != nil {
					return err
				}
				continue
			}
			return &apperr.Error{
				Code: apperr.Upstream, Message: fmt.Sprintf("%s %s", req.Method, req.Path), Err: err,
				Upstream: &apperr.UpstreamDetail{Method: req.Method, Path: req.Path, Ambiguous: !safe},
			}
		}
		if retryable(resp.StatusCode) && attempt < attempts {
			wait := c.backoff(attempt, resp.Header.Get("Retry-After"))
			drain(resp)
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return c.finish(req, resp, out)
	}
}

func (c *Client) send(ctx context.Context, method, rawURL string, body []byte, contentType string) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, rawURL, r)
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		hreq.Header.Set("Content-Type", contentType)
	}
	return c.http.Do(hreq)
}

func (c *Client) finish(req Request, resp *http.Response, out any) error {
	defer drain(resp)
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err == nil && len(b) > MaxResponseSize {
		return &apperr.Error{
			Code: apperr.Upstream, Message: fmt.Sprintf("%s %s: response larger than %d bytes", req.Method, req.Path, MaxResponseSize),
			Upstream: &apperr.UpstreamDetail{Method: req.Method, Path: req.Path, Status: resp.StatusCode, Ambiguous: !req.safe()},
		}
	}
	if err != nil {
		return &apperr.Error{
			Code: apperr.Upstream, Message: fmt.Sprintf("%s %s: read response", req.Method, req.Path), Err: err,
			Upstream: &apperr.UpstreamDetail{Method: req.Method, Path: req.Path, Status: resp.StatusCode, Ambiguous: !req.safe()},
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(req, resp.StatusCode, b)
	}
	if out == nil || len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		// A write that got a 2xx took effect even if its body is unreadable:
		// ambiguous, so the caller proves the outcome instead of assuming failure.
		return &apperr.Error{
			Code: apperr.Upstream, Message: fmt.Sprintf("%s %s: decode response", req.Method, req.Path), Err: err,
			Upstream: &apperr.UpstreamDetail{Method: req.Method, Path: req.Path, Status: resp.StatusCode, Ambiguous: !req.safe()},
		}
	}
	return nil
}

// problem covers both application/problem+json shapes Akamai returns: the
// application's (errorCode, message) and the API gateway's (type, title,
// detail, and sometimes code).
type problem struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Code       string `json:"code"`
	ErrorCode  string `json:"errorCode"`
	Message    string `json:"message"`
	IncidentID string `json:"incidentId"`
	// ErrorPaths is the Analytics error shape's per-field detail: which
	// request field was wrong, and why.
	ErrorPaths []struct {
		Path    string `json:"path"`
		Message string `json:"message"`
	} `json:"errorPaths"`
}

// detail is the most useful text a problem carries.
func (p problem) detail() string {
	d := firstNonEmpty(p.Detail, p.Message)
	var paths []string
	for _, e := range p.ErrorPaths {
		if e.Path != "" || e.Message != "" {
			paths = append(paths, strings.TrimSpace(e.Path+": "+e.Message))
		}
	}
	if len(paths) > 0 {
		d = strings.TrimSpace(d + " (" + strings.Join(paths, "; ") + ")")
	}
	return d
}

func statusError(req Request, status int, body []byte) error {
	var p problem
	_ = json.Unmarshal(body, &p) // a non-JSON error body still yields a status error
	d := &apperr.UpstreamDetail{
		Method:     req.Method,
		Path:       req.Path,
		Status:     status,
		ErrorCode:  firstNonEmpty(p.ErrorCode, p.Code),
		Title:      p.Title,
		Detail:     p.detail(),
		IncidentID: p.IncidentID,
		Ambiguous:  !req.safe() && status >= 500,
	}
	msg := fmt.Sprintf("%s %s: HTTP %d", req.Method, req.Path, status)
	if s := firstNonEmpty(d.Detail, d.Title, d.ErrorCode); s != "" {
		msg += ": " + s
	}
	return &apperr.Error{Code: codeForStatus(status), Message: msg, Upstream: d}
}

func codeForStatus(status int) apperr.Code {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return apperr.Credentials
	case http.StatusNotFound:
		return apperr.NotFound
	case http.StatusConflict, http.StatusPreconditionFailed:
		return apperr.Conflict
	default:
		return apperr.Upstream
	}
}

func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// backoff is the wait before retry number attempt: Retry-After when the
// server gives one, otherwise full jitter over an exponential step; both
// capped at MaxDelay.
func (c *Client) backoff(attempt int, retryAfter string) time.Duration {
	if d, ok := parseRetryAfter(retryAfter, time.Now(), c.MaxDelay); ok {
		return min(d, c.MaxDelay)
	}
	step := c.BaseDelay << (attempt - 1)
	if step <= 0 || step > c.MaxDelay {
		step = c.MaxDelay
	}
	return time.Duration(rand.Int64N(int64(step) + 1))
}

func parseRetryAfter(v string, now time.Time, limit time.Duration) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		if secs := int(limit / time.Second); n > secs {
			n = secs // a huge value would overflow Duration
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// IsAmbiguous reports whether err is a non-GET failure that may have taken
// effect upstream.
func IsAmbiguous(err error) bool {
	d := apperr.UpstreamOf(err)
	return d != nil && d.Ambiguous
}
