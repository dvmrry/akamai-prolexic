package ncf_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncftest"
)

// exportWorld is world() with its deployed rule: block-v4 is denied towards
// protected-dst, so one is a deny source and the other a destination.
func exportWorld() *ncftest.Store {
	s := world()
	s.Rules = []ncf.ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}}
	s.UseInRule(101, 1)
	s.UseInRule(102, 1)
	return s
}

func names(as []ncf.Alias) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Name+":"+string(a.Role))
	}
	return out
}

func TestExportBootstraps(t *testing.T) {
	res, err := ncf.Export(context.Background(), exportWorld(), nil, ncf.ExportOptions{Role: ncf.RoleDeny})
	if err != nil {
		t.Fatal(err)
	}
	f := res.File
	// Every editable alias, roles from the deployed rule; never the managed one.
	if !res.Created || f.AccountID != "A-EXAMPLE" || !slices.Equal(names(f.Aliases), []string{"block-v4:deny", "protected-dst:destination"}) {
		t.Errorf("created = %v, account = %q, aliases = %v", res.Created, f.AccountID, names(f.Aliases))
	}
	// The rule's destination is own space: declared, and reported.
	if !slices.Equal(f.OwnSpace.Aliases, []string{"protected-dst"}) || !slices.Equal(res.OwnSpaceAdded, []string{"protected-dst"}) {
		t.Errorf("own space = %v, added = %v", f.OwnSpace.Aliases, res.OwnSpaceAdded)
	}
	if len(res.Aliases) != 2 || !slices.Equal(res.Aliases[0].Added, []string{"192.0.2.0/25", "198.51.100.7/32"}) || len(res.Aliases[0].Removed) != 0 {
		t.Errorf("deltas = %+v", res.Aliases)
	}
	if _, err := ncf.Canonical(f); err != nil {
		t.Error(err)
	}
}

// Adopting drift keeps each surviving entry's metadata, adds what is live,
// drops what isn't, and leaves the caller's file untouched.
func TestExportAdoptsDrift(t *testing.T) {
	existing := desired()
	existing.Aliases[0].Entries = []ncf.Entry{
		{CIDR: "192.0.2.0/25", Ticket: "SEC-1", Reason: "scanner"},
		{CIDR: "198.51.100.99/32", Ticket: "SEC-2"},
	}
	before, _ := ncf.Canonical(existing)
	res, err := ncf.Export(context.Background(), exportWorld(), existing, ncf.ExportOptions{Role: ncf.RoleDeny})
	if err != nil {
		t.Fatal(err)
	}
	got := res.File.Aliases
	if len(got) != 1 || len(got[0].Entries) != 2 || got[0].Entries[0] != (ncf.Entry{CIDR: "192.0.2.0/25", Ticket: "SEC-1", Reason: "scanner"}) || got[0].Entries[1] != (ncf.Entry{CIDR: "198.51.100.7/32"}) {
		t.Errorf("aliases = %+v", got)
	}
	a := res.Aliases[0]
	if res.Created || !slices.Equal(a.Added, []string{"198.51.100.7/32"}) || !slices.Equal(a.Removed, []string{"198.51.100.99/32"}) {
		t.Errorf("delta = %+v", a)
	}
	// protected-dst is already declared own space in desired(): nothing added.
	if len(res.OwnSpaceAdded) != 0 {
		t.Errorf("own space added = %v", res.OwnSpaceAdded)
	}
	if after, _ := ncf.Canonical(existing); string(after) != string(before) {
		t.Error("the caller's file changed")
	}

	// All also takes the editable aliases the file doesn't name.
	res, err = ncf.Export(context.Background(), exportWorld(), existing, ncf.ExportOptions{All: true, Role: ncf.RoleDeny})
	if err != nil || !slices.Equal(names(res.File.Aliases), []string{"block-v4:deny", "protected-dst:destination"}) {
		t.Errorf("all: aliases = %v, err = %v", names(res.File.Aliases), err)
	}
}

// An alias no deployed rule uses takes the fallback role.
func TestExportFallbackRole(t *testing.T) {
	res, err := ncf.Export(context.Background(), world(), nil, ncf.ExportOptions{Role: ncf.RoleAllow})
	if err != nil || !slices.Equal(names(res.File.Aliases), []string{"block-v4:allow", "protected-dst:allow"}) {
		t.Errorf("aliases = %v, err = %v", names(res.File.Aliases), err)
	}
}

func TestExportRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(f *ncf.File, o *ncf.ExportOptions)
		kind   apperr.Kind
		want   string
	}{
		"an id that isn't live": {func(f *ncf.File, _ *ncf.ExportOptions) { f.Aliases[0].ID = 555 }, apperr.Validation, "is not live"},
		"another name":          {func(f *ncf.File, _ *ncf.ExportOptions) { f.Aliases[0].Name = "block-v6" }, apperr.Validation, "is live as block-v4"},
		"a managed alias": {func(f *ncf.File, _ *ncf.ExportOptions) {
			f.Aliases[0] = ncf.Alias{Name: "akamai-threats", ID: 900, Type: "BIG", Role: ncf.RoleDeny}
		}, apperr.Validation, "Akamai-managed"},
		"a destination fallback": {func(_ *ncf.File, o *ncf.ExportOptions) { o.Role = ncf.RoleDestination }, apperr.Usage, "deny or allow"},
	} {
		f := desired("192.0.2.0/25")
		opts := ncf.ExportOptions{Role: ncf.RoleDeny}
		tc.mutate(f, &opts)
		_, err := ncf.Export(context.Background(), exportWorld(), f, opts)
		if apperr.KindOf(err) != tc.kind || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v (kind %v)", name, err, apperr.KindOf(err))
		}
	}
}
