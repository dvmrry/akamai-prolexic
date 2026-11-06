package edgegrid

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Signer adds an EdgeGrid Authorization header to requests.
type Signer struct {
	creds Credentials
	now   func() time.Time
	nonce func() string
}

// NewSigner signs with creds.
func NewSigner(creds Credentials) *Signer {
	return &Signer{creds: creds, now: time.Now, nonce: newNonce}
}

// Sign sets req's Authorization header. It reads (and restores) the body of
// a POST to hash it, so the body must be replayable via GetBody or small
// enough to buffer.
func (s *Signer) Sign(req *http.Request) error {
	var body []byte
	if req.Method == http.MethodPost && req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return fmt.Errorf("read body to sign: %w", err)
		}
		body = b
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}
	ts := s.now().UTC().Format("20060102T15:04:05-0700")
	req.Header.Set("Authorization", s.authorization(req.Method, req.URL.Host, req.URL.RequestURI(), body, ts, s.nonce()))
	return nil
}

// authorization is the pure signing function: everything that varies is an
// argument, so the published test vectors pin it.
func (s *Signer) authorization(method, host, requestURI string, body []byte, timestamp, nonce string) string {
	prefix := fmt.Sprintf("EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		s.creds.ClientToken, s.creds.AccessToken, timestamp, nonce)

	contentHash := ""
	if method == http.MethodPost && len(body) > 0 {
		max := s.creds.MaxBody
		if max <= 0 {
			max = DefaultMaxBody
		}
		if len(body) > max {
			body = body[:max]
		}
		sum := sha256.Sum256(body)
		contentHash = base64.StdEncoding.EncodeToString(sum[:])
	}

	data := strings.Join([]string{
		strings.ToUpper(method),
		"https",
		strings.ToLower(host),
		requestURI,
		"", // canonical signed headers: this client signs none
		contentHash,
		prefix,
	}, "\t")

	signingKey := hmacBase64([]byte(s.creds.ClientSecret), timestamp)
	return prefix + "signature=" + hmacBase64([]byte(signingKey), data)
}

func hmacBase64(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Transport signs each request before passing it to Base.
type Transport struct {
	Signer *Signer
	Base   http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if err := t.Signer.Sign(req); err != nil {
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
