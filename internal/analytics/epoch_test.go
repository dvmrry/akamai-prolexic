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
}

// 2026-10-14 13:05:22 UTC is 1791983122.
func TestEpochDecodesTextDates(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Epoch
	}{
		{`"2026-10-14 13:05:22 UTC"`, 1791983122},
		{`"2026-10-14 13:05:22"`, 1791983122},
		{`"2026-10-14T13:05:22Z"`, 1791983122},
		{`"2026-10-14T13:05:22.250Z"`, 1791983122},
		{`"2026-10-14T15:05:22+02:00"`, 1791983122},
		{`"2026-10-14"`, 1791936000},
	} {
		var e Epoch
		if err := json.Unmarshal([]byte(tc.in), &e); err != nil || e != tc.want {
			t.Errorf("%s: got %d, %v; want %d", tc.in, e, err, tc.want)
		}
	}
}

// Lenient: a value prolexic can't read is blanked, never an error.
func TestEpochUnreadableIsZero(t *testing.T) {
	for _, in := range []string{`"soon"`, `false`, `true`, `{}`, `[]`, `1.5`, `"12x"`, `"2026-13-45"`, `"1.5"`, `"NaN"`, `"Inf"`} {
		e := Epoch(7)
		if err := json.Unmarshal([]byte(in), &e); err != nil || e != 0 {
			t.Errorf("%s: got %d, %v; want 0 and no error", in, e, err)
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

func TestTextTakesStringsAndNumbers(t *testing.T) {
	var v struct{ ID, Port, Missing Text }
	if err := json.Unmarshal([]byte(`{"ID":123,"Port":"443","Missing":null}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "123" || v.Port != "443" || v.Missing != "" {
		t.Errorf("v = %+v", v)
	}
}

// Seen live: attack reports send ticketId as a string, which failed every
// customer name that had an attack. Ids and measurements take a number or a
// numeric string; ticket ids are text.
func TestAttackFieldsAcceptStringsOrNumbers(t *testing.T) {
	var a Attack
	body := `{"attackId":"123","ticketId":"F-EXAMPLE-1","eventId":45,"destinations":[{"ip":"192.0.2.1","netmask":"32"}]}`
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if a.AttackID != 123 || a.TicketID != "F-EXAMPLE-1" || a.EventID != 45 {
		t.Errorf("attack = %+v", a)
	}
	var n struct{ A, B, C, D Int }
	if err := json.Unmarshal([]byte(`{"A":"406042308","B":7055033,"C":"n/a","D":null}`), &n); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n.A != 406042308 || n.B != 7055033 || n.C != 0 || n.D != 0 {
		t.Errorf("ints = %+v", n)
	}
}
