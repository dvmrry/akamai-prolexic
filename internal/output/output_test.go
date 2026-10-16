package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type nameDoc struct {
	Header
	Name string `json:"name"`
}

func (*nameDoc) SchemaID() string { return "prolexic.test.v1" }
func (d *nameDoc) WriteText(w io.Writer) error {
	_, err := fmt.Fprintf(w, "name:\t%s\nnext\n", d.Name)
	return err
}

func noRawControls(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r != '\n' && r != '\t' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			t.Errorf("raw control %U in %q", r, s)
		}
	}
}

func TestTextEscapesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	doc := &nameDoc{Name: "a\x1b[2J\x1b]0;x\x07\r\x00\u0085b\x7f"}
	if err := Write(&buf, Text, doc); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	noRawControls(t, got)
	want := "name:\ta\\x1b[2J\\x1b]0;x\\x07\\x0d\\x00\\u0085b\\x7f\nnext\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafeWriterSplitSequencesAndRawC1(t *testing.T) {
	var buf bytes.Buffer
	sw := &safeWriter{w: &buf}
	// U+0085 is C2 85, split across writes; then a raw invalid 0x9b.
	for _, p := range [][]byte{{'a', 0xc2}, {0x85, 'b', 0x9b}, []byte("é")} {
		if n, err := sw.Write(p); err != nil || n != len(p) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if err := sw.flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), `a\u0085b\x9bé`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestErrorDocTextEscapes(t *testing.T) {
	doc := NewErrorDoc(fmt.Errorf("bad \x1b[2J name\r"), 5)
	doc.Upstream = &apperr.UpstreamDetail{Method: "GET", Path: "/x\x1b[31m", ErrorCode: "E\x07",
		IncidentID: "i\u009b", Detail: "d\x1b[2J"}
	var buf bytes.Buffer
	if err := Write(&buf, Text, doc); err != nil {
		t.Fatal(err)
	}
	noRawControls(t, buf.String())
	for _, want := range []string{`bad \x1b[2J name\x0d`, `/x\x1b[31m`, `E\x07`, `i\u009b`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q in %q", want, buf.String())
		}
	}
}

func TestJSONUnchangedByEscaping(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, JSON, &nameDoc{Name: "a\x1b\u0085"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"name": "a\u001b\u0085"`) { // both escaped: still valid JSON, same value
		t.Errorf("json = %q", buf.String())
	}
}

func TestSanitizeForProgressLines(t *testing.T) {
	if got := Sanitize("block\x1b[2J-v4\r\tok\n"); got != `block\x1b[2J-v4\x0d`+"\tok\n" {
		t.Errorf("Sanitize = %q", got)
	}
}

// JSON escapes DEL and C1 controls too: encoding/json leaves them raw.
func TestJSONEscapesDELAndC1(t *testing.T) {
	var buf bytes.Buffer
	err := apperr.New(apperr.Upstream, "bad\x1b[2J del\x7f c1\u009b31m nel\u0085 é end")
	if werr := Write(&buf, JSON, NewErrorDoc(err, 5)); werr != nil {
		t.Fatal(werr)
	}
	out := buf.String()
	for _, raw := range []string{"\x7f", "\u009b", "\u0085", "\x1b"} {
		if strings.Contains(out, raw) {
			t.Errorf("raw %q in %s", raw, out)
		}
	}
	var doc struct{ Message string }
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || doc.Message != "bad\x1b[2J del\x7f c1\u009b31m nel\u0085 é end" {
		t.Errorf("round trip: %q, %v", doc.Message, err)
	}
}

// Bidi overrides, zero-width characters, the BOM, line separators, fillers
// and variation selectors are escaped in text and JSON: a right-to-left
// override can visually reverse or forge a line. Ordinary non-ASCII text is
// left alone.
func TestInvisibleCharactersAreEscaped(t *testing.T) {
	hidden := []rune{0x202e, 0x200b, 0x2066, 0xfeff, 0x2028, 0x3164, 0xe0100}
	in, plain := "a", "e-acute "+string(rune(0xe9))+" cjk "+string(rune(0x4e2d))+" emoji "+string(rune(0x1f642))
	for _, r := range hidden {
		in += string(r) + "x"
	}
	in += plain
	got := Sanitize(in)
	for _, r := range hidden {
		if strings.ContainsRune(got, r) {
			t.Errorf("text: raw U+%04X in %q", r, got)
		}
	}
	if !strings.Contains(got, "\\"+"u202e") || !strings.Contains(got, plain) {
		t.Errorf("text = %q", got)
	}
	var buf bytes.Buffer
	if err := Write(&buf, JSON, &nameDoc{Name: in}); err != nil {
		t.Fatal(err)
	}
	for _, r := range hidden {
		if strings.ContainsRune(buf.String(), r) {
			t.Errorf("json: raw U+%04X", r)
		}
	}
	var back struct{ Name string }
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || back.Name != in || !strings.Contains(buf.String(), plain) {
		t.Errorf("json round trip: %q, %v", back.Name, err)
	}
}

// failAfter accepts n writes, then fails every one: a full disk or a closed
// pipe part-way through.
type failAfter struct{ n int }

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errors.New("no space left on device")
	}
	f.n--
	return len(p), nil
}

// lineDoc ignores its write errors, as text views printing line by line do.
type lineDoc struct{ nameDoc }

func (d *lineDoc) WriteText(w io.Writer) error {
	fmt.Fprintln(w, "one")
	fmt.Fprintln(w, "two")
	fmt.Fprintln(w, "three")
	return nil
}

// A write that fails part-way is the command's error, even when the view
// doesn't check each write: output that didn't arrive must not exit 0.
func TestFailedTextWriteIsAnError(t *testing.T) {
	for _, n := range []int{0, 1, 2} {
		if err := Write(&failAfter{n: n}, Text, &lineDoc{}); err == nil || !strings.Contains(err.Error(), "no space") {
			t.Errorf("failing after %d writes: err = %v", n, err)
		}
	}
	if err := Write(&failAfter{n: 3}, Text, &lineDoc{}); err != nil {
		t.Errorf("no failure: err = %v", err)
	}
}
