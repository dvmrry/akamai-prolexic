package edgegrid

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// testdata/vectors.json holds Akamai's published signing vectors (those that
// sign no headers; this client signs none). Their tokens are placeholders.
type vectors struct {
	ClientToken  string `json:"client_token"`
	AccessToken  string `json:"access_token"`
	ClientSecret string `json:"client_secret"`
	Host         string `json:"host"`
	MaxBody      int    `json:"max_body"`
	Nonce        string `json:"nonce"`
	Timestamp    string `json:"timestamp"`
	Tests        []struct {
		Name   string `json:"name"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
		Want   string `json:"want"`
	} `json:"tests"`
}

func TestAuthorizationMatchesPublishedVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	s := NewSigner(Credentials{
		Host: v.Host, ClientToken: v.ClientToken, AccessToken: v.AccessToken,
		ClientSecret: v.ClientSecret, MaxBody: v.MaxBody,
	})
	for _, tc := range v.Tests {
		t.Run(tc.Name, func(t *testing.T) {
			got := s.authorization(tc.Method, v.Host, tc.Path, []byte(tc.Body), v.Timestamp, v.Nonce)
			if got != tc.Want {
				t.Errorf("got  %s\nwant %s", got, tc.Want)
			}
		})
	}
}

func TestTransportSignsAndPreservesBody(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
	}))
	defer srv.Close()

	s := NewSigner(Credentials{ClientToken: "akab-ct", AccessToken: "akab-at", ClientSecret: "secret"})
	s.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	s.nonce = func() string { return "n" }
	c := &http.Client{Transport: &Transport{Signer: s}}
	resp, err := c.Post(srv.URL+"/x?y=1", "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(gotAuth, "EG1-HMAC-SHA256 client_token=akab-ct;access_token=akab-at;timestamp=20260102T03:04:05+0000;nonce=n;signature=") {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody != `{"a":1}` {
		t.Errorf("body = %q", gotBody)
	}
}

func TestNonceIsUUIDv4(t *testing.T) {
	n := newNonce()
	if len(n) != 36 || n[14] != '4' {
		t.Errorf("nonce %q is not a v4 UUID", n)
	}
}

const edgerc = `
; comment
[default]
host = https://akab-hosthosthosthost-hosthosthosthost.luna.akamaiapis.net/
client_token = akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx
client_secret = "not-a-secret"
access_token = akab-yyyyyyyyyyyyyyyy-yyyyyyyyyyyyyyyy
max-body = 4096

[write]
host = h
client_token = ct
`

func writeEdgerc(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".edgerc")
	if err := os.WriteFile(p, []byte(edgerc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadFromEdgerc(t *testing.T) {
	p := writeEdgerc(t)
	c, src, err := Load(Options{Edgerc: p, Getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "akab-hosthosthosthost-hosthosthosthost.luna.akamaiapis.net" || c.ClientSecret != "not-a-secret" || c.MaxBody != 4096 {
		t.Errorf("creds = %+v", c)
	}
	if src.Kind != "edgerc" || src.Section != "default" || src.Path != p {
		t.Errorf("source = %+v", src)
	}
}

func TestLoadEnvWinsOverEdgerc(t *testing.T) {
	p := writeEdgerc(t)
	c, src, err := Load(Options{Section: "write", Edgerc: p, Getenv: env(map[string]string{
		"AKAMAI_WRITE_HOST": "w.example", "AKAMAI_WRITE_CLIENT_TOKEN": "ct",
		"AKAMAI_WRITE_CLIENT_SECRET": "cs", "AKAMAI_WRITE_ACCESS_TOKEN": "at",
	})})
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "w.example" || src.Kind != "env" || len(src.Vars) != 4 {
		t.Errorf("creds = %v, source = %+v", c, src)
	}
}

func TestLoadErrors(t *testing.T) {
	p := writeEdgerc(t)
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{"partial env", Options{Edgerc: p, Getenv: env(map[string]string{"AKAMAI_HOST": "h"})}, "missing AKAMAI_CLIENT_TOKEN"},
		{"incomplete section", Options{Section: "write", Edgerc: p, Getenv: env(nil)}, "missing client_secret in [write]"},
		{"no section", Options{Section: "nope", Edgerc: p, Getenv: env(nil)}, "no section [nope]"},
		{"no file", Options{Edgerc: filepath.Join(t.TempDir(), "x"), Getenv: env(nil)}, "no credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Load(tt.opts)
			if apperr.CodeOf(err) != apperr.Credentials || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want credentials error containing %q", err, tt.want)
			}
		})
	}
}

func TestCredentialsNeverFormatSecrets(t *testing.T) {
	c := Credentials{Host: "h", ClientToken: "TOKEN", ClientSecret: "SECRET", AccessToken: "ACCESS"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v", c, c, c)} {
		for _, secret := range []string{"TOKEN", "SECRET", "ACCESS"} {
			if strings.Contains(s, secret) {
				t.Errorf("%q reveals %s", s, secret)
			}
		}
	}
}
