package ncf_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncftest"
)

func checker() *ncf.Checker {
	c := ncf.NewChecker(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))
	c.Bogons = slices.DeleteFunc(slices.Clone(c.Bogons), func(p netip.Prefix) bool { return slices.Contains(ncf.DocumentationRanges, p) })
	return c
}

func entries(ss ...string) []ncf.Entry {
	out := make([]ncf.Entry, len(ss))
	for i, s := range ss {
		out[i] = ncf.Entry{CIDR: s}
	}
	return out
}

// world is a fake account: a deny-side SOURCE alias, an own-space DIPA
// alias, and an Akamai-managed alias.
func world() *ncftest.Store {
	s := ncftest.New()
	s.Add(ncf.LiveAlias{ID: 101, Name: "block-v4", Type: "SOURCE", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"},
		"192.0.2.0/25", "198.51.100.7")
	s.Add(ncf.LiveAlias{ID: 102, Name: "protected-dst", Type: "DIPA", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"},
		"203.0.113.0/26")
	s.Add(ncf.LiveAlias{ID: 900, Name: "akamai-threats", Type: "BIG", IPVersion: "V4", Editable: false, AccountID: "A-EXAMPLE"},
		"198.51.100.128/25")
	return s
}

func desired(blockEntries ...string) *ncf.File {
	return &ncf.File{
		Schema: ncf.DesiredSchemaID, AccountID: "A-EXAMPLE",
		OwnSpace: ncf.OwnSpace{Aliases: []string{"protected-dst"}},
		Aliases:  []ncf.Alias{{Name: "block-v4", ID: 101, Type: "SOURCE", Role: ncf.RoleDeny, Entries: entries(blockEntries...)}},
	}
}

func plan(t *testing.T, s ncf.Store, f *ncf.File, opts ncf.PlanOptions) *ncf.Plan {
	t.Helper()
	p, err := checker().MakePlan(context.Background(), s, f, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func findingCodes(fs []ncf.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, strings.TrimSpace(fmt.Sprintf("%s %s %s %s", f.Severity, f.Code, f.Alias, f.Entry)))
	}
	return out
}

var defaults = ncf.PlanOptions{MaxRemovals: ncf.DefaultMaxRemovals, LiveOwnSpace: noLive}

// live is a LiveOwnSpace reporting prefixes and asns.
func live(prefixes []ncf.OwnSpacePrefix, asns []ncf.OwnASN) ncf.LiveOwnSpace {
	return ncf.LiveOwnSpaceFunc(func(context.Context) (ncf.LiveOwnSpaceResult, error) {
		return ncf.LiveOwnSpaceResult{Prefixes: prefixes, ASNs: asns}, nil
	})
}

// noLive is a live source that reports nothing.
var noLive = live(nil, nil)

// failingLive is a live source that fails.
var failingLive = ncf.LiveOwnSpaceFunc(func(context.Context) (ncf.LiveOwnSpaceResult, error) {
	return ncf.LiveOwnSpaceResult{}, apperr.New(apperr.Upstream, "analytics down")
})

func TestPlanNoChanges(t *testing.T) {
	// Spelling differences (bare IP, host-bit-free forms) are not changes.
	p := plan(t, world(), desired("192.0.2.0/25", "198.51.100.7/32"), defaults)
	if p.Changes || len(p.Findings) != 0 || p.Aliases[0].Unchanged != 2 {
		t.Errorf("plan = %+v, findings %v", p, findingCodes(p.Findings))
	}
}

func TestPlanDiff(t *testing.T) {
	f := desired("192.0.2.0/25", "198.51.100.9", "GEO::US")
	f.Aliases[0].Entries[1].Ticket = "SEC-2"
	p := plan(t, world(), f, defaults)
	a := p.Aliases[0]
	if !p.Changes || a.ActiveVersion != "V1" {
		t.Errorf("plan = %+v", a)
	}
	if got := fmt.Sprint(a.Add); got != "[{198.51.100.9/32 SEC-2   } {GEO::US    }]" {
		t.Errorf("add = %s", got)
	}
	if got := fmt.Sprint(a.Remove); got != "[{198.51.100.7/32    }]" {
		t.Errorf("remove = %s", got)
	}
	if len(p.Findings) != 0 {
		t.Errorf("findings = %v", findingCodes(p.Findings))
	}
}

func TestPlanDigestPinsTokenAndChanges(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.9")
	d1 := plan(t, s, f, defaults).Digest
	if d2 := plan(t, s, f, defaults).Digest; d1 != d2 {
		t.Fatal("digest is not deterministic")
	}
	f2 := desired("192.0.2.0/25", "198.51.100.9")
	f2.Aliases[0].Entries[1].Reason = "metadata never reaches the API"
	if plan(t, s, f2, defaults).Digest != d1 {
		t.Error("metadata moved the digest")
	}
	s.ActivateNow(101, "192.0.2.0/25", "198.51.100.7") // same entries, new version
	if plan(t, s, f, defaults).Digest == d1 {
		t.Error("a new activeVersion didn't move the digest")
	}
}

func TestPlanOfflineErrorsSkipTheAPI(t *testing.T) {
	s := world()
	p := plan(t, s, desired("192.0.2.1/24"), defaults)
	if !ncf.HasErrors(p.Findings) || len(s.Calls) != 0 {
		t.Errorf("findings %v, calls %v", findingCodes(p.Findings), s.Calls)
	}
}

func TestPlanLiveFindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ncf.File, *ncftest.Store)
		opts   ncf.PlanOptions
		want   []string
	}{
		{"missing", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].ID = 7 }, defaults,
			[]string{"error alias_missing block-v4"}},
		{"renamed", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Name = "block-old" }, defaults,
			[]string{"error alias_mismatch block-old"}},
		{"retyped", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Type = "BIG" }, defaults,
			[]string{"error alias_mismatch block-v4"}},
		{"managed", func(f *ncf.File, _ *ncftest.Store) {
			f.Aliases[0] = ncf.Alias{Name: "akamai-threats", ID: 900, Type: "BIG", Role: ncf.RoleDeny}
		}, defaults, []string{"error alias_not_editable akamai-threats"}},
		{"family", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Entries = entries("2001:db8::/32") }, defaults,
			[]string{"error address_family block-v4 2001:db8::/32"}},
		{"own space alias", func(f *ncf.File, _ *ncftest.Store) {
			f.Aliases[0].Entries = entries("192.0.2.0/25", "198.51.100.7", "203.0.113.0/24")
		}, defaults, []string{"error own_space block-v4 203.0.113.0/24"}},
		{"own space analytics", func(f *ncf.File, _ *ncftest.Store) {},
			ncf.PlanOptions{MaxRemovals: 10, LiveOwnSpace: live([]ncf.OwnSpacePrefix{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Source: "analytics example-a/DC-A"}}, nil)}, []string{"error own_space block-v4 198.51.100.7/32"}},
		{"removal threshold", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Entries = nil },
			ncf.PlanOptions{MaxRemovals: 1, LiveOwnSpace: noLive}, []string{"error removal_threshold block-v4"}},
		{"removal threshold lifted", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Entries = nil },
			ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive}, nil},
		{"count limit", func(f *ncf.File, _ *ncftest.Store) {
			var es []string
			for i := range 51 {
				es = append(es, fmt.Sprintf("192.0.2.%d", i))
			}
			f.Aliases[0].Entries = entries(es...)
		}, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive}, []string{"error count_limit block-v4"}},
		{"missing own-space alias", func(f *ncf.File, _ *ncftest.Store) { f.OwnSpace.Aliases = []string{"nope"} }, defaults,
			[]string{"error own_space_alias nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := world(), desired("192.0.2.0/25", "198.51.100.7")
			tt.mutate(f, s)
			if got := findingCodes(plan(t, s, f, tt.opts).Findings); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPlanGeoASNNotOnDIPA(t *testing.T) {
	s := ncftest.New()
	s.Add(ncf.LiveAlias{ID: 5, Name: "dst", Type: "DIPA", IPVersion: "V4", Editable: true})
	f := &ncf.File{Schema: ncf.DesiredSchemaID, AccountID: "A-EXAMPLE", Aliases: []ncf.Alias{
		{Name: "dst", ID: 5, Type: "DIPA", Role: ncf.RoleAllow, Entries: entries("GEO::US", "ASN::64500")},
	}}
	got := findingCodes(plan(t, s, f, defaults).Findings)
	if !slices.Equal(got, []string{"error entry_type dst GEO::US", "error entry_type dst ASN::64500"}) {
		t.Errorf("findings = %q", got)
	}
}

func TestPlanUnversionedAPI(t *testing.T) {
	s := world()
	s.Unversioned = true
	a := plan(t, s, desired("192.0.2.0/25"), defaults).Aliases[0]
	if a.ActiveVersion != "" {
		t.Errorf("alias plan = %+v", a)
	}
}

func TestPlanOwnSpaceSourceFailureFailsThePlan(t *testing.T) {
	_, err := checker().MakePlan(context.Background(), world(), desired("192.0.2.0/25"), nil, ncf.PlanOptions{LiveOwnSpace: failingLive})
	if apperr.KindOf(err) != apperr.Upstream || !errors.Is(err, err) {
		t.Errorf("err = %v; a plan must not pass without its own-space sources", err)
	}
}

func TestPlanNeverFetchesAManagedOwnSpaceAlias(t *testing.T) {
	s := world()
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.OwnSpace.Aliases = []string{"akamai-threats"}
	got := findingCodes(plan(t, s, f, defaults).Findings)
	if !slices.Equal(got, []string{"error own_space_alias akamai-threats"}) {
		t.Errorf("findings = %q", got)
	}
	for _, c := range s.Calls {
		if c == "GetAlias" && s.Count("GetAlias") > 1 {
			t.Errorf("fetched more than the managed alias allows: %v", s.Calls)
		}
	}
}

func TestPlanDerivesTheRoleFromDeployedRules(t *testing.T) {
	deny := []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	permit := []ncf.ACLRule{{Index: 1, Action: "permit", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	tests := []struct {
		name     string
		rules    []ncf.ACLRule
		use      bool
		fileRole ncf.Role
		entries  []string
		want     []string
		source   string
	}{
		{"deny rule, file deny", deny, true, ncf.RoleDeny, []string{"192.0.2.0/25"}, nil, "rules"},
		{"deny rule, file allow", deny, true, ncf.RoleAllow, []string{"192.0.2.0/25"}, []string{"error role_mismatch block-v4"}, "rules"},
		{"permit rule, file deny", permit, true, ncf.RoleDeny, []string{"192.0.2.0/25"}, []string{"error role_mismatch block-v4"}, "rules"},
		// Own space (protected-dst) in a permit-side alias is fine once the
		// rules say so: the export round trip upstream hit.
		{"permit rule, own space", permit, true, ncf.RoleAllow, []string{"203.0.113.0/26"}, nil, "rules"},
		{"deny rule, own space", deny, true, ncf.RoleDeny, []string{"203.0.113.0/26"}, []string{"error own_space block-v4 203.0.113.0/26"}, "rules"},
		{"no deployed rule", nil, false, ncf.RoleDeny, []string{"192.0.2.0/25"}, nil, "file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := world()
			s.Rules = tt.rules
			if tt.use {
				s.UseInRule(101, 1)
			}
			f := desired(tt.entries...)
			f.Aliases[0].Role = tt.fileRole
			p := plan(t, s, f, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive})
			if got := findingCodes(p.Findings); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
			if p.Aliases[0].RoleSource != tt.source {
				t.Errorf("roleSource = %q, want %q", p.Aliases[0].RoleSource, tt.source)
			}
			if !tt.use && s.Count("DeployedRules") != 0 {
				t.Error("fetched the deployed rules although no alias in the file is referenced")
			}
		})
	}
}

func TestPlanUnrecognisedRuleFormIsCheckedAsDeny(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC:A-EXAMPLE:block-v4", Destination: "protected-dst"}}
	s.UseInRule(101, 1)
	p := plan(t, s, desired("192.0.2.0/25", "203.0.113.0/26"), ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive})
	got := findingCodes(p.Findings)
	want := []string{"warning role_unverified block-v4", "error own_space block-v4 203.0.113.0/26"}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || p.Aliases[0].RoleSource != "unverified" {
		t.Errorf("findings = %q, roleSource = %q; an unrecognised form must keep checks on", got, p.Aliases[0].RoleSource)
	}
}

func TestPlanCannotRelaxChecksWithoutAVerifiedSide(t *testing.T) {
	tests := map[string][]ncf.ACLRule{
		"unrecognised form":   {{Index: 1, Action: "deny", Source: "SRC:A-EXAMPLE:block-v4", Destination: "protected-dst"}},
		"rule without parsed": nil, // dropped by the adapter, so the index resolves to nothing
		"unknown action word": {{Index: 1, Action: "drop", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}},
	}
	for name, rules := range tests {
		t.Run(name, func(t *testing.T) {
			s := world()
			s.Rules = rules
			s.UseInRule(101, 1)
			f := desired("192.0.2.0/25", "203.0.113.0/26")
			f.OwnSpace.Prefixes = []string{"203.0.113.0/26"}
			f.Aliases[0].Role = ncf.RoleAllow // the file tries to relax the checks
			p := plan(t, s, f, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive})
			got := findingCodes(p.Findings)
			if !slices.Contains(got, "error own_space block-v4 203.0.113.0/26") || p.Aliases[0].RoleSource != "unverified" {
				t.Errorf("findings = %q, roleSource = %q; only a verified side may relax own-space checks", got, p.Aliases[0].RoleSource)
			}
		})
	}
}

func TestPlanOwnSpaceAliasEntryItCannotReadIsAnError(t *testing.T) {
	s := ncftest.New()
	s.Add(ncf.LiveAlias{ID: 101, Name: "block-v4", Type: "SOURCE", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, "192.0.2.0/25")
	s.Add(ncf.LiveAlias{ID: 102, Name: "protected-dst", Type: "DIPA", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, "203.0.113.0/26", "not-a-prefix")
	got := findingCodes(plan(t, s, desired("192.0.2.0/25"), defaults).Findings)
	if !slices.Equal(got, []string{"error own_space_alias protected-dst not-a-prefix"}) {
		t.Errorf("findings = %q", got)
	}
}

func TestPlanRejectsOurOwnASNOnTheDenySide(t *testing.T) {
	ours := ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: live(nil, []ncf.OwnASN{{ASN: 64500, Source: "analytics example-a/DC-A"}})}
	f := desired("192.0.2.0/25", "ASN::64500", "ASN::64501")
	got := findingCodes(plan(t, world(), f, ours).Findings)
	if !slices.Equal(got, []string{"error own_space block-v4 ASN::64500"}) {
		t.Errorf("findings = %q", got)
	}

	// A permit-side alias may name our AS, once a deployed permit rule
	// verifies the side; the file's word alone isn't enough.
	f.Aliases[0].Role = ncf.RoleAllow
	permitted := world()
	permitted.Rules = []ncf.ACLRule{{Index: 1, Action: "permit", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	permitted.UseInRule(101, 1)
	if got := findingCodes(plan(t, permitted, f, ours).Findings); len(got) != 0 {
		t.Errorf("verified allow side: findings = %q", got)
	}
	if got := findingCodes(plan(t, world(), f, ours).Findings); !slices.Equal(got, []string{"error own_space block-v4 ASN::64500"}) {
		t.Errorf("unverified allow side: findings = %q", got)
	}

	failing := ncf.PlanOptions{LiveOwnSpace: failingLive}
	if _, err := checker().MakePlan(context.Background(), world(), desired("192.0.2.0/25"), nil, failing); apperr.KindOf(err) != apperr.Upstream {
		t.Errorf("err = %v; the plan must not pass without its own-ASN source", err)
	}
}

func TestPlanOwnSpaceAliasesMustBeDIPA(t *testing.T) {
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.OwnSpace.Aliases = []string{"block-v4"} // a SOURCE alias
	got := findingCodes(plan(t, world(), f, defaults).Findings)
	if !slices.Equal(got, []string{"error own_space_alias block-v4"}) {
		t.Errorf("findings = %q", got)
	}
}

func TestPlanSaysWhatItCheckedAgainst(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	s.UseInRule(101, 1)
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.OwnSpace.Prefixes = []string{"203.0.113.128/25"}
	p := plan(t, s, f, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: live([]ncf.OwnSpacePrefix{{Prefix: netip.MustParsePrefix("198.51.100.128/25"), Source: "analytics example-a/site"}}, []ncf.OwnASN{{ASN: 64500, Source: "analytics example-a"}, {ASN: 64500, Source: "analytics example-b"}})})
	got := fmt.Sprintf("%+v", p.Checks)
	want := "{LiveChecksRan:true OwnSpace:[{Source:alias protected-dst Prefixes:1} {Source:analytics Prefixes:1} {Source:static Prefixes:1}] OwnASNs:1 DeployedRules:1}"
	if got != want {
		t.Errorf("checks = %s\nwant     %s", got, want)
	}
}

// Live own space can't be left out by accident: a plan needs a source, or an
// explicit skip that the plan reports.
func TestPlanNeedsLiveOwnSpaceOrAnExplicitSkip(t *testing.T) {
	f := desired("192.0.2.0/25", "198.51.100.7")
	if _, err := checker().MakePlan(context.Background(), world(), f, nil, ncf.PlanOptions{MaxRemovals: -1}); apperr.KindOf(err) != apperr.Bug {
		t.Errorf("no source: err = %v, want a refusal", err)
	}
	both := ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive, SkipLiveOwnSpace: true}
	if _, err := checker().MakePlan(context.Background(), world(), f, nil, both); apperr.KindOf(err) != apperr.Bug {
		t.Errorf("both: err = %v, want a refusal", err)
	}
	skipped := plan(t, world(), f, ncf.PlanOptions{MaxRemovals: -1, SkipLiveOwnSpace: true})
	if got := findingCodes(skipped.Findings); !slices.Equal(got, []string{"warning own_space_analytics_skipped"}) {
		t.Errorf("skip: findings = %q", got)
	}
}

func TestPlanReportsLiveOwnSpaceWarnings(t *testing.T) {
	warn := ncf.LiveOwnSpaceFunc(func(context.Context) (ncf.LiveOwnSpaceResult, error) {
		return ncf.LiveOwnSpaceResult{Findings: []ncf.Finding{{Severity: ncf.Warning, Code: "own_space_asn_unknown", Message: "x"}}}, nil
	})
	p := plan(t, world(), desired("192.0.2.0/25", "198.51.100.7"), ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: warn})
	if got := findingCodes(p.Findings); !slices.Equal(got, []string{"warning own_space_asn_unknown"}) {
		t.Errorf("findings = %q", got)
	}
}

func TestPlanWarnsWhenSpaceMovesBetweenDenyAliases(t *testing.T) {
	setup := func(role ncf.Role) (*ncftest.Store, *ncf.File) {
		s := world()
		s.Add(ncf.LiveAlias{ID: 103, Name: "block-b", Type: "SOURCE", IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, "198.51.100.200")
		f := desired("198.51.100.7") // 192.0.2.0/25 leaves block-v4 ...
		f.Aliases = append(f.Aliases, ncf.Alias{Name: "block-b", ID: 103, Type: "SOURCE", Role: role,
			Entries: entries("198.51.100.200", "192.0.2.0/26", "192.0.2.64/26")}) // ... and lands in block-b, split
		return s, f
	}
	s, f := setup(ncf.RoleDeny)
	got := findingCodes(plan(t, s, f, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive}).Findings)
	if !slices.Equal(got, []string{"warning cross_alias_move block-v4 192.0.2.0/25"}) {
		t.Errorf("deny to deny: findings = %q", got)
	}
	// To a verified allow alias it is a change of meaning, not a move.
	s, f = setup(ncf.RoleAllow)
	s.Rules = []ncf.ACLRule{{Index: 2, Action: "permit", Source: "SRC::A-EXAMPLE::block-b", Destination: "any"}}
	s.UseInRule(103, 2)
	if got := findingCodes(plan(t, s, f, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive}).Findings); len(got) != 0 {
		t.Errorf("deny to verified allow is a change of meaning, not a move: findings = %q", got)
	}
	// An allow role only the file states is checked as deny, so it is a move.
	s, f = setup(ncf.RoleAllow)
	if got := findingCodes(plan(t, s, f, ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive}).Findings); !slices.Equal(got, []string{"warning cross_alias_move block-v4 192.0.2.0/25"}) {
		t.Errorf("deny to unverified allow: findings = %q", got)
	}
	// A split within one alias is atomic: no warning.
	s = world()
	s.ActivateNow(101, "192.0.2.0/24", "198.51.100.7")
	if got := findingCodes(plan(t, s, desired("192.0.2.0/26", "192.0.2.64/26", "198.51.100.7"), ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: noLive}).Findings); len(got) != 0 {
		t.Errorf("split within one alias: findings = %q", got)
	}
}

// A protected-destination alias a deployed rule uses as its destination
// belongs in own space: plan warns until the file declares it.
func TestPlanWarnsAboutAnUndeclaredDestination(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	s.UseInRule(101, 1)
	s.UseInRule(102, 1)
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.OwnSpace.Aliases = nil
	if got := findingCodes(plan(t, s, f, defaults).Findings); !slices.Equal(got, []string{"warning own_space_undeclared protected-dst"}) {
		t.Errorf("undeclared: findings = %q", got)
	}
	f.OwnSpace.Aliases = []string{"protected-dst"}
	if got := findingCodes(plan(t, s, f, defaults).Findings); len(got) != 0 {
		t.Errorf("declared: findings = %q", got)
	}
}

// A destination alias in the file has role destination; calling it allow (or
// deny) is a role_mismatch, like any other disagreement with the rules.
func TestPlanDestinationRole(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	s.UseInRule(101, 1)
	s.UseInRule(102, 1)
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "protected-dst", ID: 102, Type: "DIPA", Role: ncf.RoleDestination, Entries: entries("203.0.113.0/26")})
	p := plan(t, s, f, defaults)
	if got := findingCodes(p.Findings); len(got) != 0 || p.Aliases[1].Role != ncf.RoleDestination || p.Aliases[1].RoleSource != ncf.RoleFromRules {
		t.Errorf("findings = %q, alias = %+v", got, p.Aliases[1])
	}
	f.Aliases[1].Role = ncf.RoleAllow
	if got := findingCodes(plan(t, s, f, defaults).Findings); !slices.Equal(got, []string{"error role_mismatch protected-dst"}) {
		t.Errorf("file says allow: findings = %q", got)
	}
}

// Lists in documents are [] when empty, never null: a clean plan included.
func TestCleanPlanFindingsAreAnEmptyList(t *testing.T) {
	p := plan(t, world(), desired("192.0.2.0/25", "198.51.100.7"), defaults)
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"findings":[]`) {
		t.Errorf("plan JSON: %s", b)
	}
}

// The removal limit is -1 (no limit) or at least 0. Any other negative once
// read as "no limit": a plan made with -5 would reach apply, which takes the
// reviewed plan's settings, with no removal threshold at all.
func TestMakePlanRefusesABadRemovalLimit(t *testing.T) {
	s := world()
	for _, n := range []int{-2, -5} {
		opts := defaults
		opts.MaxRemovals = n
		if _, err := checker().MakePlan(context.Background(), s, desired("192.0.2.0/25"), nil, opts); apperr.KindOf(err) != apperr.Usage {
			t.Errorf("MaxRemovals %d: err = %v", n, err)
		}
	}
}

// A role no deployed rule verifies can't relax the own-space checks
// (invariant 5): an alias no rule uses is checked as deny, whatever role the
// file gives it. Allow or destination in the file would otherwise let an
// edit switch the checks off.
func TestUnverifiedFileRoleIsCheckedAsDeny(t *testing.T) {
	for _, role := range []ncf.Role{ncf.RoleAllow, ncf.RoleDestination} {
		s := world()                                   // no deployed rules: block-v4's role comes from the file
		f := desired("192.0.2.0/25", "203.0.113.0/26") // 203.0.113.0/26 is protected-dst: own space
		f.Aliases[0].Role = role
		p := plan(t, s, f, defaults)
		if !slices.Contains(findingCodes(p.Findings), "error own_space block-v4 203.0.113.0/26") {
			t.Errorf("file role %s: findings = %v", role, findingCodes(p.Findings))
		}
		if a := p.Aliases[0]; a.RoleSource != ncf.RoleFromFile || a.Role != role {
			t.Errorf("file role %s: reported %s from %s", role, a.Role, a.RoleSource)
		}
	}
}

// End to end: a permit rule plus a rule prolexic can't read is checked as
// deny, so own space in the alias is still an error.
func TestPlanChecksAnAliasWithAnUnreadableRuleAsDeny(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "permit", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	s.UseInRule(101, 1)
	s.UseInRule(101, 2) // rule 2 has no parsed details: not in Rules
	f := desired("192.0.2.0/25", "203.0.113.0/26")
	f.Aliases[0].Role = ncf.RoleAllow
	p := plan(t, s, f, defaults)
	if !slices.Contains(findingCodes(p.Findings), "error own_space block-v4 203.0.113.0/26") || p.Aliases[0].RoleSource != ncf.RoleUnverified {
		t.Errorf("findings = %v, role source %s", findingCodes(p.Findings), p.Aliases[0].RoleSource)
	}
}

// Live own space in IPv4-mapped IPv6 form protects the IPv4 space it maps:
// the desired file's entries are unmapped, so live prefixes must be too.
func TestLiveOwnSpaceIsUnmapped(t *testing.T) {
	mapped := ncf.OwnSpacePrefix{Prefix: netip.MustParsePrefix("::ffff:198.51.100.0/120"), Source: "analytics example-a/site-a"}
	p := plan(t, world(), desired("192.0.2.0/25", "198.51.100.0/26"), ncf.PlanOptions{MaxRemovals: -1, LiveOwnSpace: live([]ncf.OwnSpacePrefix{mapped}, nil)})
	if !slices.Contains(findingCodes(p.Findings), "error own_space block-v4 198.51.100.0/26") {
		t.Errorf("findings = %v", findingCodes(p.Findings))
	}
}

// A DIPA alias holds our protected destinations and is never own-space
// checked. A deployed rule that denies it as a source blocks traffic from
// our own addresses: the plan refuses to treat that as normal.
func TestPlanRefusesADIPAAliasDeniedAsASource(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::protected-dst", Destination: "any"}}
	s.UseInRule(102, 1)
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "protected-dst", ID: 102, Type: "DIPA", Role: ncf.RoleDeny, Entries: entries("203.0.113.0/26")})
	p := plan(t, s, f, defaults)
	if !slices.Contains(findingCodes(p.Findings), "error dipa_deny_source protected-dst") {
		t.Errorf("findings = %v", findingCodes(p.Findings))
	}
}

// The digest pins the side each alias was checked on: if it changes between
// review and apply (a rule deployed in between), apply sees the digest move.
func TestDigestCoversTheRole(t *testing.T) {
	f := desired("192.0.2.0/25", "198.51.100.9")
	fromFile := plan(t, world(), f, defaults) // no deployed rule: role from the file
	ruled := world()
	ruled.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	ruled.UseInRule(101, 1)
	fromRules := plan(t, ruled, f, defaults) // same changes, side from the rules
	if fromFile.Digest == fromRules.Digest {
		t.Error("the digest doesn't change with the role's source")
	}
}

// Own space includes what the file is about to add to an own-space alias:
// otherwise a deny entry covering the new prefix passes, and the same apply
// blocks our own space.
func TestOwnSpaceCountsTheFilesOwnSpaceAliasEntries(t *testing.T) {
	f := desired("192.0.2.0/25", "203.0.113.64/26") // block-v4 covers the prefix protected-dst gains
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "protected-dst", ID: 102, Type: "DIPA", Role: ncf.RoleDestination,
		Entries: entries("203.0.113.0/26", "203.0.113.64/26")})
	p := plan(t, world(), f, defaults)
	if !slices.Contains(findingCodes(p.Findings), "error own_space block-v4 203.0.113.64/26") {
		t.Errorf("findings = %v", findingCodes(p.Findings))
	}
}

// A DIPA alias whose side can't be read is denied-as-a-source as far as
// anyone knows: the same error a verified deny source gets.
func TestPlanRefusesAnUnverifiedDIPAAlias(t *testing.T) {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "drop", Source: "SRC::A-EXAMPLE::protected-dst", Destination: "any"}}
	s.UseInRule(102, 1)
	f := desired("192.0.2.0/25", "198.51.100.7")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "protected-dst", ID: 102, Type: "DIPA", Role: ncf.RoleDestination, Entries: entries("203.0.113.0/26")})
	p := plan(t, s, f, defaults)
	if !ncf.HasErrors(p.Findings) || !slices.Contains(findingCodes(p.Findings), "error dipa_unverified protected-dst") {
		t.Errorf("findings = %v", findingCodes(p.Findings))
	}
}
