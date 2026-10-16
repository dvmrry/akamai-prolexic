package analytics

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
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

// Int is an integer field the live API may send as a number or as a numeric
// string. Anything else (an empty string, null, garbage) decodes as 0 rather
// than failing a whole customer name; it encodes as a number.
type Int int64

func (n *Int) UnmarshalJSON(b []byte) error {
	*n = 0
	s := strings.Trim(string(bytes.TrimSpace(b)), `"`)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*n = Int(v)
	} else if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && math.Abs(f) < math.MaxInt64 {
		*n = Int(f)
	}
	return nil
}

// JSONSchema describes the encoded form: an integer.
func (Int) JSONSchema() map[string]any { return map[string]any{"type": "integer"} }
