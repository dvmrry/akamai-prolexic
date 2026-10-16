package ncf

import (
	"cmp"
	"context"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// ExportOptions control Export.
type ExportOptions struct {
	// All also adds the editable live aliases the file doesn't name. A
	// bootstrap takes every editable alias regardless.
	All bool
	// Role is the role of an alias no deployed rule references; deployed
	// rules decide the rest. Deny or allow.
	Role Role
}

// ExportAlias is the change export made to one alias of the file.
type ExportAlias struct {
	Name    string   `json:"name"`
	ID      int64    `json:"id"`
	Added   []string `json:"added" doc:"Live entries the file did not have; all of them for a new alias."`
	Removed []string `json:"removed" doc:"Entries the file had that are no longer live."`
}

// ExportResult is the desired file export proposes, and how it differs from
// the one it started from.
type ExportResult struct {
	File    *File
	Created bool // there was no file: bootstrapped from every editable alias
	// Aliases are the file's aliases with their delta, sorted by name.
	Aliases []ExportAlias
	// OwnSpaceAdded are the protected-destination aliases this export
	// declared in ownSpace.aliases.
	OwnSpaceAdded []string
}

// Export reads live state and proposes the desired file that matches it.
// With existing nil it bootstraps from every editable alias; otherwise it
// updates the aliases existing names to their live entries, keeping each
// surviving entry's metadata, and refuses an alias that isn't live as the
// file describes it. existing is not modified. Reads only.
func Export(ctx context.Context, store Store, existing *File, opts ExportOptions) (*ExportResult, error) {
	if opts.Role != RoleDeny && opts.Role != RoleAllow {
		return nil, apperr.New(apperr.Usage, "the role for aliases no deployed rule references must be deny or allow, not %q", opts.Role)
	}
	live, err := store.ListAliases(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]LiveAlias{}
	for _, l := range live {
		byID[l.ID] = l
	}

	// The deployed rules decide each alias's role where one references it
	// (plan rejects a file that disagrees); opts.Role covers the rest.
	var rules RuleSet
	for _, l := range live {
		if l.Editable && len(l.ProdRules) > 0 {
			deployed, err := store.DeployedRules(ctx)
			if err != nil {
				return nil, err
			}
			rules = RulesByIndex(deployed)
			break
		}
	}
	roleOf := func(l LiveAlias, fallback Role) Role {
		if r, ok := DerivedRole(l.Name, l.ProdRules, rules); ok {
			return r
		}
		return fallback
	}

	// fetch reads one editable alias's entries, normalised and deduplicated.
	// The managed (non-editable) aliases never get here.
	fetch := func(l LiveAlias) ([]Value, error) {
		full, err := store.GetAlias(ctx, l.ID)
		if err != nil {
			return nil, err
		}
		var vals []Value
		seen := map[string]bool{}
		for _, s := range full.Entries {
			v, err := ParseLive(s)
			if err != nil {
				return nil, apperr.New(apperr.Upstream, "alias %s (%d) holds an entry export can't read: %q: %v", l.Name, l.ID, s, err)
			}
			if !seen[v.String()] {
				seen[v.String()] = true
				vals = append(vals, v)
			}
		}
		slices.SortFunc(vals, Compare)
		return vals, nil
	}
	strs := func(vs []Value) []string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = v.String()
		}
		return out
	}

	res := &ExportResult{Created: existing == nil, Aliases: []ExportAlias{}, OwnSpaceAdded: []string{}}
	var f File
	if existing == nil {
		f = File{Schema: DesiredSchemaID, OwnSpace: OwnSpace{Prefixes: []string{}, Aliases: []string{}}}
		accounts := map[string]bool{}
		for _, l := range live {
			if l.Editable && l.AccountID != "" {
				accounts[l.AccountID] = true
			}
		}
		if len(accounts) != 1 {
			return nil, apperr.New(apperr.Validation, "can't set accountId: the editable aliases report %d distinct account ids", len(accounts))
		}
		for id := range accounts {
			f.AccountID = id
		}
	} else {
		f = *existing
		f.OwnSpace.Aliases = slices.Clone(existing.OwnSpace.Aliases)
		for _, al := range f.Aliases {
			l, ok := byID[al.ID]
			switch {
			case !ok:
				return nil, apperr.New(apperr.Validation, "alias %s: id %d is not live", al.Name, al.ID)
			case l.Name != al.Name || l.Type != al.Type:
				return nil, apperr.New(apperr.Validation, "alias %s: id %d is live as %s (%s), not %s (%s)", al.Name, al.ID, l.Name, l.Type, al.Name, al.Type)
			case !l.Editable:
				return nil, apperr.New(apperr.Validation, "alias %s (%d) is Akamai-managed; it can't be exported", al.Name, al.ID)
			}
		}
	}

	var aliases []Alias
	inFile := map[int64]bool{}
	for _, al := range f.Aliases {
		inFile[al.ID] = true
		vals, err := fetch(byID[al.ID])
		if err != nil {
			return nil, err
		}
		meta := map[string]Entry{}
		have := map[string]string{} // normalised -> as the file has it
		for _, e := range al.Entries {
			if v, err := ParseAuthored(e.CIDR); err == nil {
				meta[v.String()] = e
				have[v.String()] = v.String()
			} else {
				have[e.CIDR] = e.CIDR
			}
		}
		ex := ExportAlias{Name: al.Name, ID: al.ID, Added: []string{}, Removed: []string{}}
		liveSet := map[string]bool{}
		var entries []Entry
		for _, v := range vals {
			s := v.String()
			liveSet[s] = true
			if e, ok := meta[s]; ok {
				e.CIDR = s
				entries = append(entries, e)
			} else {
				entries = append(entries, Entry{CIDR: s})
				ex.Added = append(ex.Added, s)
			}
		}
		for _, k := range sortedEntryKeys(have) {
			if !liveSet[k] {
				ex.Removed = append(ex.Removed, k)
			}
		}
		al.Entries = entries
		al.Role = roleOf(byID[al.ID], al.Role)
		aliases = append(aliases, al)
		res.Aliases = append(res.Aliases, ex)
	}
	if existing == nil || opts.All {
		for _, l := range live {
			if !l.Editable || inFile[l.ID] {
				continue
			}
			vals, err := fetch(l)
			if err != nil {
				return nil, err
			}
			al := Alias{Name: l.Name, ID: l.ID, Type: l.Type, Role: roleOf(l, opts.Role), Entries: []Entry{}}
			for _, v := range vals {
				al.Entries = append(al.Entries, Entry{CIDR: v.String()})
			}
			aliases = append(aliases, al)
			res.Aliases = append(res.Aliases, ExportAlias{Name: l.Name, ID: l.ID, Added: strs(vals), Removed: []string{}})
		}
	}
	slices.SortStableFunc(res.Aliases, func(x, y ExportAlias) int { return cmp.Compare(x.Name, y.Name) })

	// A protected-destination alias a deployed rule uses as its destination
	// is own space: declare it, so deny entries are checked against it. The
	// file is reviewed, so this is a proposal like every other export change.
	for _, al := range aliases {
		if al.Role == RoleDestination && al.Type == "DIPA" && !slices.Contains(f.OwnSpace.Aliases, al.Name) {
			f.OwnSpace.Aliases = append(f.OwnSpace.Aliases, al.Name)
			res.OwnSpaceAdded = append(res.OwnSpaceAdded, al.Name)
		}
	}
	f.Aliases = aliases
	res.File = &f
	return res, nil
}

// sortedEntryKeys orders entry strings like the canonical file: parsable ones
// by Compare, then the rest as written.
func sortedEntryKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y string) int {
		vx, ex := ParseAuthored(x)
		vy, ey := ParseAuthored(y)
		switch {
		case ex == nil && ey == nil:
			return Compare(vx, vy)
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		}
		return cmp.Compare(x, y)
	})
	return keys
}
