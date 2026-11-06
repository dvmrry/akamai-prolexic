package ncf

import (
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const canonicalFile = `{
  "$schema": "../schemas/prolexic.desired.v1.json",
  "schema": "prolexic.desired.v1",
  "accountId": "A-EXAMPLE",
  "ownSpace": {
    "prefixes": [
      "203.0.113.0/24"
    ],
    "aliases": []
  },
  "aliases": [
    {
      "name": "block-v4",
      "id": 101,
      "type": "SOURCE",
      "role": "deny",
      "entries": [
        "192.0.2.0/25",
        {
          "cidr": "198.51.100.7/32",
          "ticket": "SEC-1",
          "reason": "scanner",
          "expires": "2027-01-01"
        },
        "GEO::US"
      ]
    }
  ]
}
`

func TestDecodeAndCanonicalRoundTrip(t *testing.T) {
	f, raw, err := Decode(strings.NewReader(canonicalFile))
	if err != nil {
		t.Fatal(err)
	}
	if e := f.Aliases[0].Entries[1]; e.CIDR != "198.51.100.7/32" || e.Ticket != "SEC-1" {
		t.Errorf("object entry = %+v", e)
	}
	got, err := Canonical(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Errorf("canonical form changed the canonical file:\n%s", got)
	}
}

func TestCanonicalSortsAndNormalises(t *testing.T) {
	f := &File{Schema: DesiredSchemaID, AccountID: "A-EXAMPLE", Aliases: []Alias{
		{Name: "zz", ID: 2, Type: "SOURCE", Role: RoleDeny, Entries: []Entry{{CIDR: "geo::us"}, {CIDR: "198.51.100.9"}, {CIDR: "192.0.2.0/24"}}},
		{Name: "aa", ID: 1, Type: "DIPA", Role: RoleAllow},
	}}
	b, err := Canonical(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Index(s, `"aa"`) > strings.Index(s, `"zz"`) {
		t.Error("aliases not sorted by name")
	}
	if !strings.Contains(s, `"192.0.2.0/24",
        "198.51.100.9/32",
        "GEO::US"`) {
		t.Errorf("entries not sorted and normalised:\n%s", s)
	}
	if !strings.Contains(s, `"entries": []`) || !strings.Contains(s, `"prefixes": []`) {
		t.Errorf("empty lists must be [] not null:\n%s", s)
	}
}

func TestDecodeRefusesDuplicateKeys(t *testing.T) {
	tests := map[string]struct{ in, want string }{
		"name twice": {`{"aliases":[{"name":"a","id":1,"name":"b"}]}`, `duplicate key "name" in aliases[0]`},
		"entries twice": {`{"aliases":[{"name":"a","entries":["192.0.2.0/24"],"entries":[]}]}`,
			`duplicate key "entries" in aliases[0]`},
		"case-variant role": {`{"aliases":[{"role":"deny","Role":"allow"}]}`, `duplicate key "Role" in aliases[0] (also written as "role"`},
		"in an entry":       {`{"aliases":[{"entries":["x",{"cidr":"192.0.2.0/24","cidr":"192.0.2.1/32"}]}]}`, `duplicate key "cidr" in aliases[0].entries[1]`},
		"in ownSpace":       {`{"ownSpace":{"prefixes":[],"prefixes":["192.0.2.0/24"]}}`, `duplicate key "prefixes" in ownSpace`},
		"top level":         {`{"accountId":"a","accountid":"b"}`, `in the file`},
		"second alias":      {`{"aliases":[{"name":"a"},{"id":1,"id":2}]}`, `in aliases[1]`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := Decode(strings.NewReader(tc.in))
			if apperr.KindOf(err) != apperr.Validation || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want a validation error containing %q", err, tc.want)
			}
		})
	}
}

func TestDecodeRefusesABOM(t *testing.T) {
	_, _, err := Decode(strings.NewReader("\xEF\xBB\xBF" + canonicalFile))
	if apperr.KindOf(err) != apperr.Validation || err == nil || !strings.Contains(err.Error(), "byte-order mark; save it without one") {
		t.Errorf("err = %v", err)
	}
}

func TestDecodeAcceptsSameKeysInSiblingObjects(t *testing.T) {
	in := `{"aliases":[{"name":"a","entries":[{"cidr":"192.0.2.0/24","ticket":"T"}]},{"name":"b","entries":[{"cidr":"192.0.2.1/32","ticket":"T"}]}]}`
	if _, _, err := Decode(strings.NewReader(in)); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	tests := map[string]string{
		"unknown field":       `{"schema":"prolexic.desired.v1","bogus":1}`,
		"unknown entry field": `{"aliases":[{"entries":[{"cidr":"192.0.2.0/24","note":"x"}]}]}`,
		"object without cidr": `{"aliases":[{"entries":[{"ticket":"T-1"}]}]}`,
		"trailing JSON":       `{"schema":"prolexic.desired.v1"} {}`,
		"number entry":        `{"aliases":[{"entries":[7]}]}`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Decode(strings.NewReader(in)); apperr.KindOf(err) != apperr.Validation {
				t.Errorf("err = %v, want a validation error", err)
			}
		})
	}
	big := `{"accountId":"` + strings.Repeat("x", MaxFileSize) + `"}`
	if _, _, err := Decode(strings.NewReader(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversize: err = %v", err)
	}
}
