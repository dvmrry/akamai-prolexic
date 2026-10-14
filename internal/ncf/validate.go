package ncf

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"
)

// Severity of a finding: errors block, warnings print.
type Severity string

const (
	Error   Severity = "error"
	Warning Severity = "warning"
)

// Finding is one validation result.
type Finding struct {
	Severity Severity `json:"severity" enum:"error,warning"`
	Code     string   `json:"code" doc:"Stable machine-readable reason, e.g. bogon, own_space, host_bits."`
	Alias    string   `json:"alias,omitempty"`
	Entry    string   `json:"entry,omitempty"`
	Message  string   `json:"message"`
}

// HasErrors reports whether any finding blocks.
func HasErrors(fs []Finding) bool {
	return slices.ContainsFunc(fs, func(f Finding) bool { return f.Severity == Error })
}

// Bogons is the default list of prefixes no entry may overlap: RFC 1918,
// loopback, link-local, multicast, CGNAT, default routes, documentation
// ranges, and their IPv6 counterparts.
var Bogons = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.2.0/24", "192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "2001:db8::/32", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)

// DocumentationRanges are the bogons synthetic fixtures use. Tests drop them
// from the bogon list; nothing else should.
var DocumentationRanges = mustPrefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")

// Checker runs the checks. The zero value is not usable; use NewChecker.
type Checker struct {
	Bogons []netip.Prefix
	Today  time.Time
}

// NewChecker uses the default bogons and today's date.
func NewChecker(now time.Time) *Checker {
	return &Checker{Bogons: Bogons, Today: dateOf(now)}
}

var aliasName = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,49}$`)

var aliasTypes = []string{"SOURCE", "BIG", "DIPA"}

// Validate runs the offline checks: no credentials, no network. raw, when
// non-nil, is the file as read; it must be byte-identical to the canonical
// form.
func (c *Checker) Validate(f *File, raw []byte) []Finding {
	var out []Finding
	add := func(sev Severity, code, alias, entry, format string, args ...any) {
		out = append(out, Finding{sev, code, alias, entry, fmt.Sprintf(format, args...)})
	}

	if f.Schema != DesiredSchemaID {
		add(Error, "schema", "", "", "schema is %q, want %q", f.Schema, DesiredSchemaID)
	}
	if f.AccountID == "" {
		add(Error, "account_id", "", "", "accountId is required")
	}

	var own []netip.Prefix
	for _, s := range f.OwnSpace.Prefixes {
		v, err := ParseAuthored(s)
		if err != nil || v.Kind() != KindPrefix {
			add(Error, "own_space_prefix", "", s, "ownSpace prefix: %v", errOr(err, "not a prefix"))
			continue
		}
		own = append(own, v.Prefix())
	}

	names, ids := map[string]bool{}, map[int64]bool{}
	for _, a := range f.Aliases {
		if !aliasName.MatchString(a.Name) {
			add(Error, "alias_name", a.Name, "", "alias name must be 3–50 lower-case letters, digits, dashes or underscores, starting with a letter")
		}
		if names[a.Name] {
			add(Error, "duplicate_alias", a.Name, "", "alias %q appears more than once", a.Name)
		}
		names[a.Name] = true
		if a.ID <= 0 {
			add(Error, "alias_id", a.Name, "", "alias id must be positive")
		} else if ids[a.ID] {
			add(Error, "duplicate_alias", a.Name, "", "alias id %d appears more than once", a.ID)
		}
		ids[a.ID] = true
		if !slices.Contains(aliasTypes, a.Type) {
			add(Error, "alias_type", a.Name, "", "type must be SOURCE, BIG or DIPA, not %q", a.Type)
		}
		if a.Role != RoleDeny && a.Role != RoleAllow {
			add(Error, "alias_role", a.Name, "", "role must be deny or allow, not %q", a.Role)
		}
		out = append(out, c.validateEntries(a, own)...)
	}

	if raw != nil {
		if canon, err := Canonical(f); err == nil && !bytes.Equal(raw, canon) {
			add(Error, "not_canonical", "", "", "the file is not in canonical form; it is machine-owned: change it with add, remove or export, or run fmt")
		}
	}
	return out
}

func (c *Checker) validateEntries(a Alias, own []netip.Prefix) []Finding {
	var out []Finding
	add := func(sev Severity, code, entry, format string, args ...any) {
		out = append(out, Finding{sev, code, a.Name, entry, fmt.Sprintf(format, args...)})
	}
	seen := map[string]bool{}
	var prefixes []netip.Prefix
	for _, e := range a.Entries {
		v, err := ParseAuthored(e.CIDR)
		if err != nil {
			add(Error, "entry", e.CIDR, "%v", err)
			continue
		}
		key := v.String()
		if seen[key] {
			add(Error, "duplicate_entry", key, "%s appears more than once", key)
			continue
		}
		seen[key] = true
		for _, field := range []struct{ name, val string }{{"added", e.Added}, {"expires", e.Expires}} {
			if field.val == "" {
				continue
			}
			if _, err := ParseDate(field.val); err != nil {
				add(Error, "metadata_date", key, "%s %q is not YYYY-MM-DD", field.name, field.val)
			}
		}
		if e.Expires != "" {
			if d, err := ParseDate(e.Expires); err == nil && d.Before(c.Today) {
				add(Warning, "expired", key, "expired on %s", e.Expires)
			}
		}
		if v.Kind() != KindPrefix {
			continue
		}
		p := v.Prefix()
		if i := slices.IndexFunc(c.Bogons, p.Overlaps); i >= 0 {
			add(Error, "bogon", key, "%s overlaps the bogon range %s", key, c.Bogons[i])
			continue // a bogon would only add noise to the checks below
		}
		if a.Role == RoleDeny {
			for _, o := range own {
				if p.Overlaps(o) {
					add(Error, "own_space", key, "deny entry %s overlaps own space %s (static list)", key, o)
				}
			}
		}
		prefixes = append(prefixes, p)
	}
	for _, p := range prefixes {
		for _, q := range prefixes {
			if p != q && Contains(q, p) {
				add(Warning, "contained", p.String(), "%s is already covered by %s", p, q)
				break
			}
		}
	}
	return out
}

func dateOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
