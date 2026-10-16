// Package output is the CLI's output contract: every command emits one
// Document, rendered as JSON when stdout is not a terminal and as readable
// text when it is. Every JSON document carries a "schema" field naming its
// published JSON Schema (schemas/<id>.json).
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Document is a command's result.
//
// Implementations embed Header, return a constant from SchemaID, and render
// their text form with WriteText. Text is for people; JSON is the contract.
type Document interface {
	SchemaID() string
	WriteText(w io.Writer) error
	setSchema(id string)
	stamp(at time.Time, version string)
}

// Header carries the "schema" field, and when and by which prolexic the
// document was made: an apply or verify document is a record someone files.
// Embed it in every Document.
type Header struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generatedAt,omitempty" doc:"When the document was made (RFC 3339, UTC)."`
	Prolexic    string `json:"prolexic,omitempty" doc:"The prolexic version that made it."`
}

func (h *Header) setSchema(id string) { h.Schema = id }

func (h *Header) stamp(at time.Time, version string) {
	h.GeneratedAt, h.Prolexic = at.UTC().Format(time.RFC3339), version
}

// Stamp records when and by which version doc was made.
func Stamp(doc Document, at time.Time, version string) { doc.stamp(at, version) }

// Format selects the rendering.
type Format string

const (
	Auto Format = "auto"
	JSON Format = "json"
	Text Format = "text"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch f := Format(s); f {
	case Auto, JSON, Text:
		return f, nil
	}
	return "", apperr.New(apperr.Usage, "--format must be auto, json or text, not %q", s)
}

// Resolve turns Auto into JSON or Text for the writer.
func (f Format) Resolve(w io.Writer) Format {
	if f != Auto {
		return f
	}
	if IsTerminal(w) {
		return Text
	}
	return JSON
}

// IsTerminal reports whether w is a character device.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Write stamps doc's schema id and renders it in the resolved format.
func Write(w io.Writer, f Format, doc Document) error {
	doc.setSchema(doc.SchemaID())
	if f.Resolve(w) == Text {
		sw := &safeWriter{w: w}
		if err := doc.WriteText(sw); err != nil {
			return err
		}
		return sw.flush()
	}
	return writeJSON(w, doc)
}

func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeControls(buf.Bytes()))
	return err
}

// escapeControls escapes DEL and the C1 controls (U+0080 to U+009F), which
// encoding/json leaves raw but a terminal or log viewer may act on. Such
// bytes can only occur inside JSON strings, so a \\u escape is always valid.
func escapeControls(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == 0x7f:
			out = append(out, `\u007f`...)
		case b[i] == 0xc2 && i+1 < len(b) && b[i+1] >= 0x80 && b[i+1] <= 0x9f:
			out = fmt.Appendf(out, `\u%04x`, b[i+1])
			i++
		default:
			out = append(out, b[i])
		}
	}
	return out
}

// ErrorSchemaID names the error document's schema.
const ErrorSchemaID = "prolexic.error.v1"

// ErrorDoc is written to stderr when a command fails.
type ErrorDoc struct {
	Header
	Code     int                    `json:"code" doc:"The process exit code."`
	Kind     string                 `json:"kind" enum:"bug,usage,credentials,not_found,upstream,validation,drift,conflict,cancelled"`
	Message  string                 `json:"message"`
	Upstream *apperr.UpstreamDetail `json:"upstream,omitempty"`
}

func (*ErrorDoc) SchemaID() string { return ErrorSchemaID }

func (d *ErrorDoc) WriteText(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "prolexic: %s\n", d.Message); err != nil {
		return err
	}
	u := d.Upstream
	if u == nil {
		return nil
	}
	// What support and a retry decision need, without the JSON form.
	line := fmt.Sprintf("  upstream: %s %s", u.Method, u.Path)
	if u.Status != 0 {
		line += fmt.Sprintf(" -> %d", u.Status)
	}
	if u.ErrorCode != "" {
		line += " " + u.ErrorCode
	}
	if u.IncidentID != "" {
		line += ", incident " + u.IncidentID
	}
	if u.Ambiguous {
		line += " (the write may or may not have taken effect)"
	}
	_, err := fmt.Fprintln(w, line)
	return err
}

// NewErrorDoc describes err for stderr, with the exit code the front chose
// for it.
func NewErrorDoc(err error, exitCode int) *ErrorDoc {
	return &ErrorDoc{
		Code:     exitCode,
		Kind:     string(apperr.KindOf(err)),
		Message:  err.Error(),
		Upstream: apperr.UpstreamOf(err),
	}
}
