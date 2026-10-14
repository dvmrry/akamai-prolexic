package ncf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Plan is the diff of a desired file against live, with every finding.
type Plan struct {
	AccountID string      `json:"accountId"`
	Digest    string      `json:"digest" doc:"sha256 over each alias's id, name, activeVersion and changes; apply --expect-digest must match."`
	Changes   bool        `json:"changes"`
	Aliases   []AliasPlan `json:"aliases"`
	Findings  []Finding   `json:"findings"`
}

// AliasPlan is one alias's diff.
type AliasPlan struct {
	Name          string `json:"name"`
	ID            int64  `json:"id"`
	Type          string `json:"type"`
	IPVersion     string `json:"ipVersion"`
	Role          Role   `json:"role"`
	ActiveVersion string `json:"activeVersion" doc:"The conflict token: apply refuses if it moved. Empty when the API doesn't expose versions."`
	ProdVersion   string `json:"prodVersion"`
	// VersionsRemaining is absent when the API doesn't expose versions.
	VersionsRemaining *int    `json:"versionsRemaining,omitempty"`
	Add               []Entry `json:"add"`
	Remove            []Entry `json:"remove"`
	Unchanged         int     `json:"unchanged"`

	// desired is the full canonical entry list apply writes.
	desired []string
	live    LiveAlias
}

// Changed reports whether apply would write this alias.
func (a AliasPlan) Changed() bool { return len(a.Add) > 0 || len(a.Remove) > 0 }

// PlanOptions tune the live checks.
type PlanOptions struct {
	// MaxRemovals is the most entries one alias may lose in one apply
	// before the plan errors; a truncated file must not empty a blocklist.
	// Negative means no limit.
	MaxRemovals int
	// OwnSpace adds own-space prefixes (Prolexic Analytics); nil adds none.
	OwnSpace OwnSpaceSource
}

// DefaultMaxRemovals is the removal threshold without --max-removals.
const DefaultMaxRemovals = 10

// geoASNTypes are the alias types that accept GEO:: and ASN:: entries.
// Source-side types only, per techdocs: SOURCE and BIG; DIPA holds
// destination IPs.
var geoASNTypes = []string{"SOURCE", "BIG"}

// countLimits are the entry-count bounds per alias type.
var countLimits = map[string][2]int{
	"SOURCE": {0, 50},
	"DIPA":   {0, 50},
	"BIG":    {51, 19999},
}

// MakePlan validates f offline, then against live. If the offline checks
// fail, it returns without contacting the API. An error return means the
// plan couldn't be computed (credentials, upstream); findings are in the
// Plan.
func (c *Checker) MakePlan(ctx context.Context, store Store, f *File, raw []byte, opts PlanOptions) (*Plan, error) {
	p := &Plan{AccountID: f.AccountID, Aliases: []AliasPlan{}, Findings: c.Validate(f, raw)}
	if HasErrors(p.Findings) {
		return p, nil
	}
	add := func(sev Severity, code, alias, entry, format string, args ...any) {
		p.Findings = append(p.Findings, Finding{sev, code, alias, entry, fmt.Sprintf(format, args...)})
	}

	all, err := store.ListAliases(ctx)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeOf(err), err, "list aliases")
	}
	byID, byName := map[int64]LiveAlias{}, map[string]LiveAlias{}
	for _, l := range all {
		byID[l.ID], byName[l.Name] = l, l
	}

	own, err := c.ownSpace(ctx, store, f, byName, opts.OwnSpace, add)
	if err != nil {
		return nil, err
	}

	for _, a := range f.Aliases {
		l, ok := byID[a.ID]
		switch {
		case !ok:
			add(Error, "alias_missing", a.Name, "", "no alias with id %d", a.ID)
			continue
		case l.Name != a.Name:
			add(Error, "alias_mismatch", a.Name, "", "alias %d is named %q live, not %q", a.ID, l.Name, a.Name)
			continue
		case l.Type != a.Type:
			add(Error, "alias_mismatch", a.Name, "", "alias %d is type %s live, not %s; a type change means recreating the alias", a.ID, l.Type, a.Type)
			continue
		case !l.Editable:
			add(Error, "alias_not_editable", a.Name, "", "alias %d is Akamai-managed", a.ID)
			continue
		case f.AccountID != "" && l.AccountID != "" && l.AccountID != f.AccountID:
			add(Error, "account_mismatch", a.Name, "", "alias %d belongs to another account", a.ID)
			continue
		}
		full, err := store.GetAlias(ctx, a.ID)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeOf(err), err, "get alias %s", a.Name)
		}
		ap, ok := c.diff(a, full, add)
		if !ok {
			continue
		}
		c.liveChecks(a, full, &ap, own, opts, add)
		p.Aliases = append(p.Aliases, ap)
	}

	slices.SortFunc(p.Aliases, func(x, y AliasPlan) int { return cmpString(x.Name, y.Name) })
	for _, a := range p.Aliases {
		p.Changes = p.Changes || a.Changed()
	}
	p.Digest = digest(p.Aliases)
	return p, nil
}

func (c *Checker) diff(a Alias, l LiveAlias, add func(Severity, string, string, string, string, ...any)) (AliasPlan, bool) {
	ap := AliasPlan{
		Name: a.Name, ID: a.ID, Type: l.Type, IPVersion: l.IPVersion, Role: a.Role,
		ActiveVersion: l.ActiveVersion, ProdVersion: l.ProdVersion,
		Add: []Entry{}, Remove: []Entry{}, live: l,
	}
	live := map[string]bool{}
	ok := true
	for _, s := range l.Entries {
		v, err := ParseLive(s)
		if err != nil {
			add(Error, "live_entry", a.Name, s, "live entry can't be parsed, so the alias can't be diffed: %v", err)
			ok = false
			continue
		}
		live[v.String()] = true
	}
	if !ok {
		return ap, false
	}
	desired := map[string]bool{}
	for _, e := range a.Entries {
		v, _ := ParseAuthored(e.CIDR) // Validate already rejected unparsable entries
		key := v.String()
		desired[key] = true
		ap.desired = append(ap.desired, key)
		if live[key] {
			ap.Unchanged++
		} else {
			e.CIDR = key
			ap.Add = append(ap.Add, e)
		}
	}
	for key := range live {
		if !desired[key] {
			ap.Remove = append(ap.Remove, Entry{CIDR: key})
		}
	}
	sortByValue(ap.Add)
	sortByValue(ap.Remove)
	sortCanonical(ap.desired)
	return ap, true
}

func (c *Checker) liveChecks(a Alias, l LiveAlias, ap *AliasPlan, own []OwnSpacePrefix, opts PlanOptions, add func(Severity, string, string, string, string, ...any)) {
	for _, e := range a.Entries {
		v, _ := ParseAuthored(e.CIDR)
		key := v.String()
		switch v.Kind() {
		case KindPrefix:
			if v.Is4() != (l.IPVersion == "V4") {
				add(Error, "address_family", a.Name, key, "%s doesn't match the alias's IP version %s", key, l.IPVersion)
			}
			if a.Role == RoleDeny {
				for _, o := range own {
					if v.Prefix().Overlaps(o.Prefix) {
						add(Error, "own_space", a.Name, key, "deny entry %s overlaps own space %s (%s)", key, o.Prefix, o.Source)
					}
				}
			}
		case KindGeo, KindASN:
			if !slices.Contains(geoASNTypes, l.Type) {
				add(Error, "entry_type", a.Name, key, "%s alias %s can't hold GEO:: or ASN:: entries", l.Type, a.Name)
			}
		}
	}

	if lim, ok := countLimits[l.Type]; ok {
		if n := len(a.Entries); n < lim[0] || n > lim[1] {
			add(Error, "count_limit", a.Name, "", "%s aliases hold %d–%d entries; this one would hold %d", l.Type, lim[0], lim[1], n)
		}
	}

	if opts.MaxRemovals >= 0 && len(ap.Remove) > opts.MaxRemovals {
		add(Error, "removal_threshold", a.Name, "", "would remove %d entries, more than the limit of %d; pass --max-removals to allow it", len(ap.Remove), opts.MaxRemovals)
	}

	if l.Versions > 0 {
		left := max(MaxVersions-l.Versions, 0)
		ap.VersionsRemaining = &left
		if ap.Changed() {
			switch {
			case left == 0:
				add(Error, "versions_exhausted", a.Name, "", "the alias has used all %d versions; rotate it (new alias, repoint the rule)", MaxVersions)
			case left < 3:
				add(Warning, "versions_low", a.Name, "", "%d of %d versions left; this apply spends one", left, MaxVersions)
			}
		}
	}
}

// ownSpace gathers the live own-space prefixes: the own-space aliases'
// entries and the extra source. The static list is checked offline.
func (c *Checker) ownSpace(ctx context.Context, store Store, f *File, byName map[string]LiveAlias, extra OwnSpaceSource, add func(Severity, string, string, string, string, ...any)) ([]OwnSpacePrefix, error) {
	var out []OwnSpacePrefix
	for _, name := range f.OwnSpace.Aliases {
		l, ok := byName[name]
		if !ok {
			add(Error, "own_space_alias", name, "", "own-space alias %q doesn't exist", name)
			continue
		}
		full, err := store.GetAlias(ctx, l.ID)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeOf(err), err, "get own-space alias %s", name)
		}
		for _, s := range full.Entries {
			if v, err := ParseLive(s); err == nil && v.Kind() == KindPrefix {
				out = append(out, OwnSpacePrefix{v.Prefix(), "alias " + name})
			}
		}
	}
	if extra != nil {
		more, err := extra(ctx)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeOf(err), err, "own space from Prolexic Analytics")
		}
		out = append(out, more...)
	}
	return out, nil
}

// digest pins what apply will do: per alias, its identity, conflict token
// and changes. Metadata isn't included; it never reaches the API.
func digest(aliases []AliasPlan) string {
	type pin struct {
		ID            int64    `json:"id"`
		Name          string   `json:"name"`
		ActiveVersion string   `json:"activeVersion"`
		Add           []string `json:"add"`
		Remove        []string `json:"remove"`
	}
	pins := make([]pin, len(aliases))
	for i, a := range aliases {
		pins[i] = pin{a.ID, a.Name, a.ActiveVersion, cidrs(a.Add), cidrs(a.Remove)}
	}
	b, _ := json.Marshal(pins) // slices of plain structs always marshal
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cidrs(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.CIDR
	}
	return out
}

func sortByValue(es []Entry) {
	slices.SortFunc(es, func(a, b Entry) int {
		va, _ := ParseLive(a.CIDR)
		vb, _ := ParseLive(b.CIDR)
		return Compare(va, vb)
	})
}

func sortCanonical(ss []string) {
	slices.SortFunc(ss, func(a, b string) int {
		va, _ := ParseLive(a)
		vb, _ := ParseLive(b)
		return Compare(va, vb)
	})
}

// SameEntries reports whether two entry lists are the same set after
// normalisation; unparsable entries never match.
func SameEntries(a, b []string) bool {
	set := func(ss []string) (map[string]bool, bool) {
		m := map[string]bool{}
		for _, s := range ss {
			v, err := ParseLive(s)
			if err != nil {
				return nil, false
			}
			m[v.String()] = true
		}
		return m, true
	}
	ma, oka := set(a)
	mb, okb := set(b)
	if !oka || !okb || len(ma) != len(mb) {
		return false
	}
	for k := range ma {
		if !mb[k] {
			return false
		}
	}
	return true
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
