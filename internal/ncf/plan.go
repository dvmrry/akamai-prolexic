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
	Name          string  `json:"name"`
	ID            int64   `json:"id"`
	Type          string  `json:"type"`
	IPVersion     string  `json:"ipVersion"`
	Role          Role    `json:"role" doc:"The effective role: derived from the deployed rules when one references the alias, else the file's."`
	RoleSource    string  `json:"roleSource" enum:"rules,file,unverified"`
	ActiveVersion string  `json:"activeVersion" doc:"The conflict token: apply refuses if it moved. Empty when the API doesn't expose versions."`
	ProdVersion   string  `json:"prodVersion"`
	Add           []Entry `json:"add"`
	Remove        []Entry `json:"remove"`
	Unchanged     int     `json:"unchanged"`

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
	// OwnASNs supplies our own AS numbers (from the BGP sessions); a deny-side
	// ASN:: entry naming one would block our own network. nil adds none.
	OwnASNs OwnASNSource
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
	ownASNs := map[uint32]string{}
	if opts.OwnASNs != nil {
		asns, err := opts.OwnASNs(ctx)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeOf(err), err, "own AS numbers from Prolexic Analytics")
		}
		for _, a := range asns {
			if _, seen := ownASNs[a.ASN]; !seen {
				ownASNs[a.ASN] = a.Source // first source wins: stable messages
			}
		}
	}

	// Deployed rules decide each alias's side; fetch them once, and only
	// when some alias in the file is referenced by one.
	var rules map[int]ACLRule
	for _, a := range f.Aliases {
		if l, ok := byID[a.ID]; ok && len(l.ProdRules) > 0 {
			deployed, err := store.DeployedRules(ctx)
			if err != nil {
				return nil, apperr.Wrap(apperr.CodeOf(err), err, "read the deployed ACL rules")
			}
			rules = RulesByIndex(deployed)
			break
		}
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
		full, err := withEntries(ctx, store, l)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeOf(err), err, "get alias %s", a.Name)
		}
		// The deployed rules' side wins over the file's; a disagreement is an
		// error, since the file's role would switch own-space checks off or on
		// wrongly.
		roleSource, fileDenySide := RoleFromFile, a.DenySide()
		if derived, ok := DerivedRole(a.Name, l.ProdRules, rules); ok {
			roleSource = RoleFromRules
			if derived != a.Role {
				add(Error, "role_mismatch", a.Name, "", "the file says role %s, but the deployed rules use the alias %s", a.Role, sideOf(derived))
			}
			a.Role = derived
		} else if len(l.ProdRules) > 0 {
			// Deployed rules use the alias but its side can't be read: only a
			// verified derivation may relax checks, so it is checked as deny.
			roleSource = RoleUnverified
			add(Warning, "role_unverified", a.Name, "", "deployed rules %v reference the alias in a form or with an action prolexic doesn't recognise; own-space checks apply whatever the file says", l.ProdRules)
			a.Role = RoleDeny
		}
		ap, ok := c.diff(a, full, add)
		if !ok {
			continue
		}
		ap.RoleSource = roleSource
		checked := own
		if a.DenySide() && !fileDenySide {
			// Validate checked the static list against the file's role, which
			// said allow; the live side is deny, so check it here too.
			checked = append(staticOwnSpace(f), own...)
		}
		c.liveChecks(a, full, &ap, checked, ownASNs, opts, add)
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
		Add: []Entry{}, Remove: []Entry{}, live: l, desired: []string{}, // never nil: emptying an alias sends []
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

func (c *Checker) liveChecks(a Alias, l LiveAlias, ap *AliasPlan, own []OwnSpacePrefix, ownASNs map[uint32]string, opts PlanOptions, add func(Severity, string, string, string, string, ...any)) {
	for _, e := range a.Entries {
		v, _ := ParseAuthored(e.CIDR)
		key := v.String()
		switch v.Kind() {
		case KindPrefix:
			if v.Is4() != (l.IPVersion == "V4") {
				add(Error, "address_family", a.Name, key, "%s doesn't match the alias's IP version %s", key, l.IPVersion)
			}
			if a.DenySide() {
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
			if src, ours := ownASNs[v.ASN()]; ours && v.Kind() == KindASN && a.DenySide() {
				add(Error, "own_space", a.Name, key, "deny entry %s is our own AS (%s): it would block our own network", key, src)
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
		if !l.Editable {
			// Akamai-managed aliases can hold hundreds of thousands of entries
			// and are never fetched.
			add(Error, "own_space_alias", name, "", "own-space alias %q is Akamai-managed; list its prefixes in ownSpace.prefixes instead", name)
			continue
		}
		if l.Type != "DIPA" {
			add(Error, "own_space_alias", name, "", "own-space alias %q is %s; own-space aliases are protected-destination (DIPA) aliases", name, l.Type)
			continue
		}
		full, err := withEntries(ctx, store, l)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeOf(err), err, "get own-space alias %s", name)
		}
		for _, s := range full.Entries {
			v, err := ParseLive(s)
			if err != nil || v.Kind() != KindPrefix {
				// Skipping it would shrink own space silently.
				add(Error, "own_space_alias", name, s, "own-space alias entry %q isn't a prefix prolexic can read", s)
				continue
			}
			out = append(out, OwnSpacePrefix{v.Prefix(), "alias " + name})
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

// withEntries reads a listed alias's entries from its active version by id:
// the list already gave the token, so a plan makes one list call instead of
// one per alias. An API without versions falls back to GetAlias.
func withEntries(ctx context.Context, store Store, l LiveAlias) (LiveAlias, error) {
	if l.ActiveVersion == "" {
		return store.GetAlias(ctx, l.ID)
	}
	v, err := store.GetVersion(ctx, l.ID, l.ActiveVersion)
	if err != nil {
		return LiveAlias{}, err
	}
	l.Entries = v.Entries
	return l, nil
}

// staticOwnSpace is the desired file's static own-space list, parsed (Validate
// already reported any it couldn't parse).
func staticOwnSpace(f *File) []OwnSpacePrefix {
	var out []OwnSpacePrefix
	for _, s := range f.OwnSpace.Prefixes {
		if v, err := ParseAuthored(s); err == nil && v.Kind() == KindPrefix {
			out = append(out, OwnSpacePrefix{v.Prefix(), "static"})
		}
	}
	return out
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
