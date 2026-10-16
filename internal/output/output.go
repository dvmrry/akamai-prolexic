// Package output is the CLI's output contract: every command emits one
// Document, rendered as JSON when stdout is not a terminal and as readable
// text when it is. Every JSON document carries a "schema" field naming its
// published JSON Schema (schemas/<id>.json).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

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
}

// Header carries the "schema" field. Embed it in every Document.
type Header struct {
	Schema string `json:"schema"`
}

func (h *Header) setSchema(id string) { h.Schema = id }

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
		return doc.WriteText(w)
	}
	return writeJSON(w, doc)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
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
