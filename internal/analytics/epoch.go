package analytics

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
)

// epochMillisFrom is the smallest value taken as milliseconds. 1e12 seconds is
// year 33658, 1e12 milliseconds is September 2001.
const epochMillisFrom = 1_000_000_000_000

// Epoch is a UNIX time in seconds. The spec says integer seconds, but the live
// API sends some of these as a string, in milliseconds, or as a text date, so
// decoding is lenient. It always encodes as an integer of seconds.
type Epoch int64

// textLayouts are the text dates the API sends. Zone-less ones are UTC.
var textLayouts = []string{
	"2006-01-02 15:04:05 UTC",
	"2006-01-02 15:04:05",
	time.RFC3339Nano, // also reads RFC 3339 without fractional seconds
	"2006-01-02",
}

// UnmarshalJSON accepts a number or a numeric string, in seconds or
// milliseconds (values from 1e12 up), a text date ("2026-10-14 13:05:22 UTC",
// the same without "UTC", RFC 3339, or "2026-10-14"), and null or "" as 0.
// Anything else (false, objects, fractions, unknown strings) decodes to 0
// without an error: a field prolexic can't read is blanked, not a failure.
func (e *Epoch) UnmarshalJSON(b []byte) error {
	*e = 0
	b = bytes.TrimSpace(b)
	s := string(b)
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &s); err != nil {
			return nil
		}
		s = strings.TrimSpace(s)
	}
	if s == "" || s == "null" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*e = fromNumber(n)
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f == math.Trunc(f) && math.Abs(f) < 1e18 {
			*e = fromNumber(int64(f))
		}
		return nil
	}
	for _, layout := range textLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			*e = Epoch(t.Unix())
			return nil
		}
	}
	return nil
}

func fromNumber(n int64) Epoch {
	if n >= epochMillisFrom {
		n /= 1000
	}
	return Epoch(n)
}

// JSONSchema describes the encoded form: an integer of seconds.
func (Epoch) JSONSchema() map[string]any { return map[string]any{"type": "integer"} }

// Unix returns the time as int64 seconds.
func (e Epoch) Unix() int64 { return int64(e) }
