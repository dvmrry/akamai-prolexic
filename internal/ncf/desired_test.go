package ncf

import (
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

const canonicalFile = `{
  "$schema": "../schemas/prolexic.desired.v1.json",
  "accountId": "A-EXAMPLE",
  "aliases": [
    {
      "entries": [
        "192.0.2.0/25",
        {
          "cidr": "198.51.100.7/32",
          "expires": "2027-01-01",
          "reason": "scanner",
          "ticket": "SEC-1"
        },
        "GEO::US"
      ],
      "id": 101,
      "name": "block-v4",
      "role": "deny",
      "type": "SOURCE"
    }
  ],
  "ownSpace": {
    "aliases": [],
    "prefixes": [
      "203.0.113.0/24"
    ]
  },
  "schema": "prolexic.desired.v1"
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
