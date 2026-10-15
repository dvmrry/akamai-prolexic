package analytics

import (
	"bytes"
	"encoding/json"
)

// Text is a string field the live API may also send as a number (ids,
// ports). It decodes a string, a number (kept as written) or null, and
// encodes as a string, so a type drift can't fail a whole customer name.
type Text string

func (t *Text) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0 || string(b) == "null":
		*t = ""
	case b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*t = Text(s)
	default:
		*t = Text(b) // a number, bool or other literal, as written
	}
	return nil
}

// JSONSchema describes the encoded form: a string.
func (Text) JSONSchema() map[string]any { return map[string]any{"type": "string"} }
