package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

func TestWriteJSONStampsSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Auto, NewErrorDoc(apperr.New(apperr.Drift, "digest moved"), 7)); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if got["schema"] != ErrorSchemaID || got["code"] != float64(7) || got["kind"] != "drift" {
		t.Errorf("doc = %v", got)
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Text, NewErrorDoc(fmt.Errorf("boom"), 1)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "prolexic: boom") {
		t.Errorf("text = %q", buf.String())
	}
}

func TestParseFormat(t *testing.T) {
	if _, err := ParseFormat("yaml"); apperr.KindOf(err) != apperr.Usage {
		t.Errorf("ParseFormat(yaml) err = %v, want usage", err)
	}
}

// The text error keeps what support and a retry decision need.
func TestErrorTextCarriesUpstreamDetail(t *testing.T) {
	err := &apperr.Error{Kind: apperr.Upstream, Message: "activate block-v4 V3",
		Upstream: &apperr.UpstreamDetail{Method: "PATCH", Path: "/x/activate", Status: 503, ErrorCode: "UNAVAILABLE", IncidentID: "inc-1", Ambiguous: true}}
	var buf bytes.Buffer
	if werr := Write(&buf, Text, NewErrorDoc(err, 5)); werr != nil {
		t.Fatal(werr)
	}
	want := "prolexic: activate block-v4 V3\n  upstream: PATCH /x/activate -> 503 UNAVAILABLE, incident inc-1 (the write may or may not have taken effect)\n"
	if buf.String() != want {
		t.Errorf("text = %q\nwant   %q", buf.String(), want)
	}
}
