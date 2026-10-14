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
	if err := Write(&buf, Auto, NewErrorDoc(apperr.New(apperr.Drift, "digest moved"))); err != nil {
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
	if err := Write(&buf, Text, NewErrorDoc(fmt.Errorf("boom"))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "prolexic: boom") {
		t.Errorf("text = %q", buf.String())
	}
}

func TestParseFormat(t *testing.T) {
	if _, err := ParseFormat("yaml"); apperr.CodeOf(err) != apperr.Usage {
		t.Errorf("ParseFormat(yaml) err = %v, want usage", err)
	}
}
