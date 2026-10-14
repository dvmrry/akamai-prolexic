package ncf

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// testChecker is the default checker minus the documentation ranges, which
// synthetic fixtures must use; everything else is real.
func testChecker() *Checker {
	c := NewChecker(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	c.Bogons = slices.DeleteFunc(slices.Clone(c.Bogons), func(p netip.Prefix) bool { return slices.Contains(DocumentationRanges, p) })
	return c
}

func testFile(aliases ...Alias) *File {
	return &File{
		Schema: DesiredSchemaID, AccountID: "A-EXAMPLE",
		OwnSpace: OwnSpace{Prefixes: []string{"203.0.113.0/24"}},
		Aliases:  aliases,
	}
}

func entries(ss ...string) []Entry {
	out := make([]Entry, len(ss))
	for i, s := range ss {
		out[i] = Entry{CIDR: s}
	}
	return out
}

// codes renders findings as "severity code alias entry" for comparison.
func codes(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, strings.TrimSpace(fmt.Sprintf("%s %s %s %s", f.Severity, f.Code, f.Alias, f.Entry)))
	}
	return out
}

func TestValidateClean(t *testing.T) {
	f := testFile(Alias{Name: "block-v4", ID: 1, Type: "SOURCE", Role: RoleDeny, Entries: entries("192.0.2.0/24", "GEO::US", "ASN::64500")})
	if fs := testChecker().Validate(f, nil); len(fs) != 0 {
		t.Errorf("findings = %v", codes(fs))
	}
}

func TestValidateFindings(t *testing.T) {
	expired := Entry{CIDR: "198.51.100.0/24", Expires: "2026-10-13"}
	badDate := Entry{CIDR: "198.51.100.64/26", Added: "14/10/2026"}
	f := &File{Schema: "prolexic.desired.v0", OwnSpace: OwnSpace{Prefixes: []string{"203.0.113.0/24", "nope"}}, Aliases: []Alias{
		{Name: "block-v4", ID: 1, Type: "SOURCE", Role: RoleDeny, Entries: append(entries(
			"192.0.2.1/24",                 // host bits
			"10.1.0.0/16",                  // RFC 1918
			"100.64.0.0/10",                // CGNAT
			"0.0.0.0/0",                    // default route
			"203.0.113.128/25",             // own space
			"192.0.2.0/25", "192.0.2.0/25", // duplicate
			"192.0.2.0/26", // contained in /25
			"GEO::ZZ",
		), expired, badDate)},
		{Name: "allow", ID: 1, Type: "LIST", Role: "maybe", Entries: entries("203.0.113.0/24")},
		{Name: "Bad", ID: 0, Type: "DIPA", Role: RoleAllow},
	}}
	got := codes(testChecker().Validate(f, nil))
	want := []string{
		"error schema",
		"error account_id",
		"error own_space_prefix  nope",
		"error entry block-v4 192.0.2.1/24",
		"error bogon block-v4 10.1.0.0/16",
		"error bogon block-v4 100.64.0.0/10",
		"error bogon block-v4 0.0.0.0/0",
		"error own_space block-v4 203.0.113.128/25",
		"error duplicate_entry block-v4 192.0.2.0/25",
		"error entry block-v4 GEO::ZZ",
		"warning expired block-v4 198.51.100.0/24",
		"error metadata_date block-v4 198.51.100.64/26",
		"warning contained block-v4 192.0.2.0/26",
		"warning contained block-v4 198.51.100.64/26",
		"error duplicate_alias allow",
		"error alias_type allow",
		"error alias_role allow",
		"error alias_name Bad",
		"error alias_id Bad",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %q\n want %q", got, want)
	}
}

func TestValidateAllowSideMayHoldOwnSpace(t *testing.T) {
	f := testFile(Alias{Name: "trusted", ID: 1, Type: "SOURCE", Role: RoleAllow, Entries: entries("203.0.113.0/24")})
	if fs := testChecker().Validate(f, nil); len(fs) != 0 {
		t.Errorf("findings = %v", codes(fs))
	}
}

func TestValidateDefaultBogonsRejectDocumentationRanges(t *testing.T) {
	f := testFile(Alias{Name: "block-v4", ID: 1, Type: "SOURCE", Role: RoleDeny, Entries: entries("192.0.2.0/24")})
	got := codes(NewChecker(time.Now()).Validate(f, nil))
	if !slices.Contains(got, "error bogon block-v4 192.0.2.0/24") {
		t.Errorf("findings = %v", got)
	}
}

func TestValidateRequiresCanonicalForm(t *testing.T) {
	f := testFile(Alias{Name: "block-v4", ID: 1, Type: "SOURCE", Role: RoleDeny, Entries: entries("192.0.2.0/24")})
	canon, err := Canonical(f)
	if err != nil {
		t.Fatal(err)
	}
	if fs := testChecker().Validate(f, canon); len(fs) != 0 {
		t.Errorf("canonical: findings = %v", codes(fs))
	}
	hand := strings.Replace(string(canon), "  ", "    ", 1)
	if got := codes(testChecker().Validate(f, []byte(hand))); !slices.Equal(got, []string{"error not_canonical"}) {
		t.Errorf("hand-edited: findings = %v", got)
	}
}
