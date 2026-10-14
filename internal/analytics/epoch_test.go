package analytics

import (
	"encoding/json"
	"testing"
)

func TestEpochDecode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Epoch
	}{
		{`1700000000`, 1700000000},
		{`"1700000000"`, 1700000000},
		{`"1700000000000"`, 1700000000},
		{`1700000000000`, 1700000000},
		{`1700000000.0`, 1700000000},
		{`null`, 0},
		{`""`, 0},
		{`0`, 0},
	} {
		var e Epoch
		if err := json.Unmarshal([]byte(tc.in), &e); err != nil || e != tc.want {
			t.Errorf("%s: got %d, %v; want %d", tc.in, e, err, tc.want)
		}
	}
	for _, in := range []string{`"soon"`, `false`, `true`, `{}`, `[]`, `1.5`, `"12x"`} {
		var e Epoch
		if err := json.Unmarshal([]byte(in), &e); err == nil {
			t.Errorf("%s: decoded to %d, want an error", in, e)
		}
	}
}

func TestEpochEncodesAsSeconds(t *testing.T) {
	var s struct {
		A Epoch `json:"a"`
		B Epoch `json:"b,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"a":"1700000000000"}`), &s); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(s)
	if string(out) != `{"a":1700000000}` {
		t.Errorf("encoded %s", out)
	}
}
