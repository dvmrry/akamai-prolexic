package ncf_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

// canonical is f's canonical bytes: a file as add and remove last wrote it.
func canonical(t *testing.T, f *ncf.File) []byte {
	t.Helper()
	b, err := ncf.Canonical(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func changeCodes(fs []ncf.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, string(f.Severity)+" "+f.Code+" "+f.Entry)
	}
	return out
}

func TestAddEntries(t *testing.T) {
	f := desired("192.0.2.0/25")
	ch, err := checker().AddEntries(f, canonical(t, f), ncf.AddRequest{
		Alias: "block-v4", Entries: []string{"198.51.100.9", "2001:db8::/48"}, Ticket: "SEC-1", Reason: "scanner", Expires: "2027-01-31",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Blocked() || len(ch.Findings) != 0 {
		t.Fatalf("blocked = %v, findings = %v", ch.Blocked(), changeCodes(ch.Findings))
	}
	want := []ncf.Entry{
		{CIDR: "198.51.100.9/32", Ticket: "SEC-1", Reason: "scanner", Added: "2026-10-14", Expires: "2027-01-31"},
		{CIDR: "2001:db8::/48", Ticket: "SEC-1", Reason: "scanner", Added: "2026-10-14", Expires: "2027-01-31"},
	}
	if !slices.Equal(ch.Entries, want) {
		t.Errorf("entries = %+v", ch.Entries)
	}
	if got := ch.File.Aliases[0].Entries; len(got) != 3 || got[1] != want[0] {
		t.Errorf("file entries = %+v", got)
	}
	if len(f.Aliases[0].Entries) != 1 {
		t.Errorf("the input file changed: %+v", f.Aliases[0].Entries)
	}
}

// A change is blocked by any error, and by a warning about an entry being
// added: nothing new goes in with a question over it. A warning about an
// entry already there doesn't block.
func TestAddEntriesBlocked(t *testing.T) {
	for name, tc := range map[string]struct {
		have, add []string
		raw       func(t *testing.T, f *ncf.File) []byte
		want      string
	}{
		"already present":         {[]string{"192.0.2.0/25"}, []string{"192.0.2.0/25"}, nil, "error already_present 192.0.2.0/25"},
		"present as another form": {[]string{"198.51.100.7/32"}, []string{"198.51.100.7"}, nil, "error already_present 198.51.100.7/32"},
		"twice in the request":    {nil, []string{"198.51.100.9", "198.51.100.9/32"}, nil, "error already_present 198.51.100.9/32"},
		"not an entry":            {nil, []string{"198.51.100.0/33"}, nil, "error entry 198.51.100.0/33"},
		"a bogon":                 {nil, []string{"10.0.0.0/8"}, nil, "error bogon 10.0.0.0/8"},
		"warning on the addition": {[]string{"198.51.100.0/24"}, []string{"198.51.100.9"}, nil, "warning contained 198.51.100.9/32"},
		"hand-edited file": {[]string{"192.0.2.0/25"}, []string{"198.51.100.9"},
			func(t *testing.T, f *ncf.File) []byte { return append(canonical(t, f), '\n') }, "error not_canonical "},
	} {
		f := desired(tc.have...)
		raw := canonical(t, f)
		if tc.raw != nil {
			raw = tc.raw(t, f)
		}
		ch, err := checker().AddEntries(f, raw, ncf.AddRequest{Alias: "block-v4", Entries: tc.add, Ticket: "SEC-1", Reason: "r"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ch.Blocked() || !slices.Contains(changeCodes(ch.Findings), tc.want) {
			t.Errorf("%s: blocked = %v, findings = %v", name, ch.Blocked(), changeCodes(ch.Findings))
		}
	}

	// A warning about an entry already in the file doesn't block an addition.
	f := desired("198.51.100.0/24", "198.51.100.7")
	ch, err := checker().AddEntries(f, canonical(t, f), ncf.AddRequest{Alias: "block-v4", Entries: []string{"192.0.2.0/25"}, Ticket: "SEC-1", Reason: "r"})
	if err != nil || ch.Blocked() || !slices.Contains(changeCodes(ch.Findings), "warning contained 198.51.100.7/32") {
		t.Errorf("old warning: blocked = %v, findings = %v, err = %v", ch.Blocked(), changeCodes(ch.Findings), err)
	}
}

// Requests a front could get wrong are refused, whatever the front checked.
func TestChangeRequestsRefused(t *testing.T) {
	f := desired("192.0.2.0/25")
	raw := canonical(t, f)
	ok := ncf.AddRequest{Alias: "block-v4", Entries: []string{"198.51.100.9"}, Ticket: "SEC-1", Reason: "r"}
	for name, tc := range map[string]struct {
		mutate func(r *ncf.AddRequest)
		kind   apperr.Kind
		want   string
	}{
		"no alias":     {func(r *ncf.AddRequest) { r.Alias = "nope" }, apperr.Validation, `no alias "nope"`},
		"no entries":   {func(r *ncf.AddRequest) { r.Entries = nil }, apperr.Usage, "no entries"},
		"blank ticket": {func(r *ncf.AddRequest) { r.Ticket = "  " }, apperr.Usage, "ticket"},
		"blank reason": {func(r *ncf.AddRequest) { r.Reason = "" }, apperr.Usage, "reason"},
		"bad expiry":   {func(r *ncf.AddRequest) { r.Expires = "31/01/2027" }, apperr.Usage, "YYYY-MM-DD"},
	} {
		req := ok
		tc.mutate(&req)
		if _, err := checker().AddEntries(f, raw, req); apperr.KindOf(err) != tc.kind || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v (kind %v)", name, err, apperr.KindOf(err))
		}
	}
	if _, err := checker().RemoveEntries(f, raw, ncf.RemoveRequest{Alias: "block-v4", Entries: []string{"192.0.2.0/25"}, Ticket: ""}); apperr.KindOf(err) != apperr.Usage {
		t.Errorf("remove without a ticket: err = %v", err)
	}
}

func TestRemoveEntries(t *testing.T) {
	f := desired("192.0.2.0/25")
	f.Aliases[0].Entries = append(f.Aliases[0].Entries, ncf.Entry{CIDR: "198.51.100.7/32", Ticket: "SEC-0", Reason: "old"})
	ch, err := checker().RemoveEntries(f, canonical(t, f), ncf.RemoveRequest{Alias: "block-v4", Entries: []string{"198.51.100.7"}, Ticket: "SEC-2"})
	if err != nil || ch.Blocked() {
		t.Fatalf("blocked = %v, findings = %v, err = %v", ch.Blocked(), changeCodes(ch.Findings), err)
	}
	// The removed entry keeps the metadata it had, for the record.
	if len(ch.Entries) != 1 || ch.Entries[0] != (ncf.Entry{CIDR: "198.51.100.7/32", Ticket: "SEC-0", Reason: "old"}) {
		t.Errorf("removed = %+v", ch.Entries)
	}
	if got := ch.File.Aliases[0].Entries; len(got) != 1 || got[0].CIDR != "192.0.2.0/25" || len(f.Aliases[0].Entries) != 2 {
		t.Errorf("file = %+v, input = %+v", got, f.Aliases[0].Entries)
	}

	ch, err = checker().RemoveEntries(f, canonical(t, f), ncf.RemoveRequest{Alias: "block-v4", Entries: []string{"203.0.113.9", "bogus"}, Ticket: "SEC-2"})
	if err != nil || !ch.Blocked() || !slices.Contains(changeCodes(ch.Findings), "error not_present 203.0.113.9/32") || !slices.Contains(changeCodes(ch.Findings), "error entry bogus") {
		t.Errorf("blocked = %v, findings = %v, err = %v", ch.Blocked(), changeCodes(ch.Findings), err)
	}
}
