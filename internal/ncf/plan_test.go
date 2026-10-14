package ncf_test

import (
	"context"
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

var defaults = ncf.PlanOptions{MaxRemovals: ncf.DefaultMaxRemovals}

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
	if !p.Changes || a.ActiveVersion != 1 || a.VersionsRemaining == nil || *a.VersionsRemaining != 9 {
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
			ncf.PlanOptions{MaxRemovals: 10, OwnSpace: func(context.Context) ([]ncf.OwnSpacePrefix, error) {
				return []ncf.OwnSpacePrefix{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Source: "analytics example-a/DC-A"}}, nil
			}}, []string{"error own_space block-v4 198.51.100.7/32"}},
		{"removal threshold", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Entries = nil },
			ncf.PlanOptions{MaxRemovals: 1}, []string{"error removal_threshold block-v4"}},
		{"removal threshold lifted", func(f *ncf.File, _ *ncftest.Store) { f.Aliases[0].Entries = nil },
			ncf.PlanOptions{MaxRemovals: -1}, nil},
		{"count limit", func(f *ncf.File, _ *ncftest.Store) {
			var es []string
			for i := range 51 {
				es = append(es, fmt.Sprintf("192.0.2.%d", i))
			}
			f.Aliases[0].Entries = entries(es...)
		}, ncf.PlanOptions{MaxRemovals: -1}, []string{"error count_limit block-v4"}},
		{"versions low", func(f *ncf.File, s *ncftest.Store) {
			s.AddVersions(101, 7)
			f.Aliases[0].Entries = entries("192.0.2.0/25")
		}, defaults, []string{"warning versions_low block-v4"}},
		{"versions exhausted", func(f *ncf.File, s *ncftest.Store) {
			s.AddVersions(101, 9)
			f.Aliases[0].Entries = entries("192.0.2.0/25")
		}, defaults, []string{"error versions_exhausted block-v4"}},
		{"versions exhausted but no change", func(f *ncf.File, s *ncftest.Store) { s.AddVersions(101, 9) }, defaults, nil},
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

func TestPlanGeoASNOnlyOnSource(t *testing.T) {
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
	if a.ActiveVersion != 0 || a.VersionsRemaining != nil {
		t.Errorf("alias plan = %+v", a)
	}
}

func TestPlanOwnSpaceSourceFailureFailsThePlan(t *testing.T) {
	_, err := checker().MakePlan(context.Background(), world(), desired("192.0.2.0/25"), nil, ncf.PlanOptions{
		OwnSpace: func(context.Context) ([]ncf.OwnSpacePrefix, error) {
			return nil, apperr.New(apperr.Upstream, "analytics down")
		},
	})
	if apperr.CodeOf(err) != apperr.Upstream || !errors.Is(err, err) {
		t.Errorf("err = %v; a plan must not pass without its own-space sources", err)
	}
}
