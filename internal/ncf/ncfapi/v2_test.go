package ncfapi

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

// v2Server fakes the NCF v2 routes a test registers, recording requests.
type v2Server struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]func(w http.ResponseWriter, r *http.Request, body []byte)
	seen   []string
}

func newV2(t *testing.T) (*V2, *v2Server) {
	f := &v2Server{t: t, routes: map[string]func(http.ResponseWriter, *http.Request, []byte){}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + strings.TrimPrefix(r.URL.Path, v2Path)
		f.mu.Lock()
		f.seen = append(f.seen, key+"?"+r.URL.RawQuery)
		h, ok := f.routes[key]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"errorCode":"NOT_FOUND","message":"no fake route ` + key + `"}`))
			return
		}
		h(w, r, body)
	}))
	t.Cleanup(srv.Close)
	c := akamai.New(edgegrid.Credentials{Host: strings.TrimPrefix(srv.URL, "http://"), ClientToken: "ct", ClientSecret: "cs", AccessToken: "at"}, akamai.Options{Scheme: "http"})
	c.MaxAttempts = 1
	return NewV2(c), f
}

func (f *v2Server) json(route, body string) {
	f.routes[route] = func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.Write([]byte(body)) }
}

const aliasesV2 = `[
  {"accountId":"A-EXAMPLE","aliasId":101,"aliasName":"block-v4","aliasType":"SOURCE","ipVersion":"V4",
   "isCustomerEditable":true,"activeVersion":{"version":"V3","entriesCount":2},
   "prodVersion":{"version":"V2","entriesCount":1,"aclRules":[4]},"versions":["V3","V2","V1"]},
  {"accountId":"A-EXAMPLE","aliasId":900,"aliasName":"akamai-threats","aliasType":"BIG","ipVersion":"V4",
   "isCustomerEditable":false,"activeVersion":{"version":"V7","entriesCount":150000}}
]`

func TestV2ListAndGetAlias(t *testing.T) {
	s, f := newV2(t)
	f.json("GET /aliases", aliasesV2)
	f.json("GET /aliases/101/versions/active", `{"aliasId":101,"version":"V3","isActive":true,"entries":["192.0.2.0/25","198.51.100.7"]}`)

	all, err := s.ListAliases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if all[0].ActiveVersion != "V3" || all[0].ProdVersion != "V2" || all[0].Versions != 3 || all[0].Entries != nil {
		t.Errorf("list = %+v", all[0])
	}
	if all[1].Editable || all[1].ProdVersion != "" || all[1].EntriesCount != 150000 {
		t.Errorf("managed alias = %+v", all[1])
	}

	l, err := s.GetAlias(context.Background(), 101)
	if err != nil {
		t.Fatal(err)
	}
	if l.ActiveVersion != "V3" || l.ProdVersion != "V2" || len(l.Entries) != 2 || l.Type != "SOURCE" {
		t.Errorf("alias = %+v", l)
	}
	if _, err := s.GetAlias(context.Background(), 7); apperr.CodeOf(err) != apperr.NotFound {
		t.Errorf("missing alias: err = %v", err)
	}
}

func TestV2GetAliasTakesTheTokenFromTheEntriesResponse(t *testing.T) {
	// The list says V3 but a version was activated before the entries were
	// read: the token must match the entries, or apply would pin the wrong
	// version.
	s, f := newV2(t)
	f.json("GET /aliases", aliasesV2)
	f.json("GET /aliases/101/versions/active", `{"aliasId":101,"version":"V4","isActive":true,"entries":["192.0.2.0/25"]}`)
	l, err := s.GetAlias(context.Background(), 101)
	if err != nil || l.ActiveVersion != "V4" {
		t.Errorf("alias = %+v, err = %v", l, err)
	}
}

func TestV2ListVersionsPages(t *testing.T) {
	s, f := newV2(t)
	f.routes["GET /aliases/101/versions"] = func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Query().Get("size") != "100" {
			t.Errorf("size = %q", r.URL.Query().Get("size"))
		}
		switch r.URL.Query().Get("page") {
		case "0":
			w.Write([]byte(`{"content":[{"version":"V3","isActive":true},{"version":"V2"}],"last":false}`))
		default:
			w.Write([]byte(`{"content":[{"version":"V1"}],"last":true}`))
		}
	}
	vs, err := s.ListVersions(context.Background(), 101)
	if err != nil || len(vs) != 3 || !vs[0].Active || vs[2].Version != "V1" {
		t.Errorf("versions = %+v, err = %v", vs, err)
	}
}

func TestV2CreateVersionIsInactiveAndDerivedFromTheToken(t *testing.T) {
	s, f := newV2(t)
	var got map[string]any
	f.routes["POST /aliases/101/versions"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		json.Unmarshal(body, &got)
		w.WriteHeader(201)
		w.Write([]byte(`{"aliasId":101,"version":"V4","isActive":false,"entries":["192.0.2.0/25"]}`))
	}
	alias := ncf.LiveAlias{ID: 101, Name: "block-v4", Type: "SOURCE", IPVersion: "V4", ActiveVersion: "V3"}
	v, err := s.CreateVersion(context.Background(), alias, []string{"192.0.2.0/25"}, "prolexic apply sha256:abc")
	if err != nil || v.Version != "V4" || v.Active {
		t.Fatalf("v = %+v, err = %v", v, err)
	}
	// isActive must be sent, and false: the API defaults it to true.
	if got["isActive"] != false || got["sourceVersion"] != "V3" || got["comments"] != "prolexic apply sha256:abc" {
		t.Errorf("request = %v", got)
	}
	if _, present := got["isActive"]; !present {
		t.Error("isActive omitted; the API would default it to true")
	}
}

func TestV2CreateBigVersionUploadsAFile(t *testing.T) {
	s, f := newV2(t)
	fields := map[string]string{}
	f.routes["POST /big-aliases/104/versions"] = func(w http.ResponseWriter, r *http.Request, body []byte) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		mr := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(p)
			fields[p.FormName()] = string(b)
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"aliasId":104,"version":"V2","isActive":true}`))
	}
	alias := ncf.LiveAlias{ID: 104, Name: "block-big", Type: "BIG", IPVersion: "V4", ActiveVersion: "V1"}
	v, err := s.CreateVersion(context.Background(), alias, []string{"198.51.100.0/32", "198.51.100.1/32"}, "c")
	if err != nil || v.Version != "V2" || !v.Active {
		t.Fatalf("v = %+v, err = %v", v, err)
	}
	if fields["aliasName"] != "block-big" || fields["ipVersion"] != "V4" || fields["file"] != "198.51.100.0/32\n198.51.100.1/32\n" {
		t.Errorf("fields = %q", fields)
	}
}

func TestV2CreateWithoutAVersionIsAmbiguous(t *testing.T) {
	s, f := newV2(t)
	f.routes["POST /aliases/101/versions"] = func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}
	_, err := s.CreateVersion(context.Background(), ncf.LiveAlias{ID: 101, Type: "SOURCE", ActiveVersion: "V3"}, []string{"192.0.2.0/25"}, "")
	if d := apperr.UpstreamOf(err); d == nil || !d.Ambiguous {
		t.Errorf("err = %v; a create whose version is unknown must be proven from the version list", err)
	}
}

func TestV2ActivateAndGetVersion(t *testing.T) {
	s, f := newV2(t)
	f.routes["PATCH /aliases/101/versions/V4/activate"] = func(w http.ResponseWriter, _ *http.Request, _ []byte) { w.WriteHeader(204) }
	f.json("GET /aliases/101/versions/V4", `{"aliasId":101,"version":"V4","isActive":true,"entries":["192.0.2.0/25"]}`)
	if err := s.Activate(context.Background(), 101, "V4"); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetVersion(context.Background(), 101, "V4")
	if err != nil || !v.Active || len(v.Entries) != 1 {
		t.Errorf("v = %+v, err = %v", v, err)
	}
}

func TestV2ListVersionsNeverStopsEarly(t *testing.T) {
	tests := map[string][]string{
		"totalPages only":  {`{"content":[{"version":"V2"}],"totalPages":2}`, `{"content":[{"version":"V1"}],"totalPages":2}`},
		"no paging fields": {`{"content":[{"version":"V2"}]}`, `{"content":[{"version":"V1"}]}`, `{"content":[]}`},
	}
	for name, pages := range tests {
		t.Run(name, func(t *testing.T) {
			s, f := newV2(t)
			n := 0
			f.routes["GET /aliases/101/versions"] = func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.Write([]byte(pages[n]))
				n++
			}
			vs, err := s.ListVersions(context.Background(), 101)
			if err != nil || len(vs) != 2 {
				t.Errorf("versions = %+v, err = %v", vs, err)
			}
		})
	}
}

func TestV2CreateNeedsASourceVersion(t *testing.T) {
	s, _ := newV2(t)
	_, err := s.CreateVersion(context.Background(), ncf.LiveAlias{ID: 101, Name: "block-v4", Type: "SOURCE"}, []string{"192.0.2.0/25"}, "")
	if err == nil || !strings.Contains(err.Error(), "no source version") {
		t.Errorf("err = %v", err)
	}
}
