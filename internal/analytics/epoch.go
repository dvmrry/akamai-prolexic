package analytics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// epochMillisFrom is the smallest value taken as milliseconds. 1e12 seconds is
// year 33658, 1e12 milliseconds is September 2001.
const epochMillisFrom = 1_000_000_000_000

// Epoch is a UNIX time in seconds. The spec says integer seconds, but the live
// API sends some of these as a string, or in milliseconds, so decoding takes a
// number or a numeric string in either unit. It always encodes as an integer
// of seconds.
type Epoch int64

// UnmarshalJSON accepts a number or a numeric string, in seconds or
// milliseconds (values from 1e12 up), and null or "" as 0. Anything else is an
// error.
func (e *Epoch) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		*e = 0
		return nil
	}
	s := string(b)
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			*e = 0
			return nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil || f != float64(int64(f)) {
			return fmt.Errorf("epoch: %s is not an integer time", b)
		}
		n = int64(f)
	}
	if n >= epochMillisFrom {
		n /= 1000
	}
	*e = Epoch(n)
	return nil
}

// JSONSchema describes the encoded form: an integer of seconds.
func (Epoch) JSONSchema() map[string]any { return map[string]any{"type": "integer"} }

// Unix returns the time as int64 seconds.
func (e Epoch) Unix() int64 { return int64(e) }
