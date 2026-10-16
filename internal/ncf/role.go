package ncf

import (
	"net/netip"
	"slices"
	"strings"
)

// Role sources, as a plan reports them.
const (
	RoleFromRules = "rules" // derived from the deployed ACL rules
	RoleFromFile  = "file"  // no deployed rule references the alias; the file's role stands
	// RoleUnverified: deployed rules reference the alias but its side can't
	// be read, so it is checked as deny whatever the file says.
	RoleUnverified = "unverified"
)

// DerivedRole says what the deployed rules use an alias for. It is deny when
// any deployed deny rule names the alias as its source (who is blocked),
// allow when a permit rule names it as its source (who is let through), and
// destination when rules name it only as a destination (where a rule applies:
// addresses being protected). It is unknown (ok false) unless some rule at
// one of the alias's indexes actually names it: a rule in an address form
// this code doesn't recognise must not turn own-space checks off.
func DerivedRole(name string, prodRules []int, rules RuleSet) (Role, bool) {
	named, unknownAction, permitSource := false, false, false
	for _, idx := range prodRules {
		at := rules[idx]
		if len(at) != 1 || !at[0].parsed() {
			// A rule uses the alias that prolexic can't read (missing, no
			// parsed form, or an index two rules share): it might deny, so
			// the side is unverified, not derived from the rules that can be
			// read.
			unknownAction = true
			continue
		}
		r := at[0]
		src, dst := refersTo(r.Source, name), refersTo(r.Destination, name)
		// An address that mentions the alias in a form we don't recognise
		// might be it: unknown, so a recognised use elsewhere in the rule
		// can't mask a deny source.
		if (mentions(r.Source, name) && !src) || (mentions(r.Destination, name) && !dst) {
			unknownAction = true
		}
		if !src && !dst {
			continue
		}
		named = true
		switch action := strings.ToLower(r.Action); {
		case action == "deny":
			if src {
				return RoleDeny, true
			}
		case !permitActions[action] && src:
			// An action word we don't know (drop? block?) on a source use
			// might deny: it must not derive allow.
			unknownAction = true
		case src:
			permitSource = true
		}
	}
	// The alias list's indexes and the deployed rules come from separate
	// reads. A deployed rule that mentions the alias outside its indexes (a
	// deployment between the reads) might deny it: unverified.
	if namedOutside(name, prodRules, rules) {
		unknownAction = true
	}
	if unknownAction || !named {
		return "", false
	}
	if permitSource {
		return RoleAllow, true
	}
	return RoleDestination, true
}

// permitActions are the action words that let traffic through. Only these
// derive allow; any other word on a source use leaves the side unknown.
var permitActions = map[string]bool{"permit": true, "accept": true, "allow": true}

// mentions reports whether an address names the alias as a whole name
// anywhere in it: an occurrence whose neighbours aren't name characters
// ([a-z0-9_-]). A name that is only part of a longer name doesn't count.
func mentions(addr, name string) bool {
	addr, name = strings.ToLower(addr), strings.ToLower(name)
	if name == "" {
		return false
	}
	for i := 0; ; {
		j := strings.Index(addr[i:], name)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(name)
		if (start == 0 || !nameChar(addr[start-1])) && (end == len(addr) || !nameChar(addr[end])) {
			return true
		}
		i = start + 1
	}
}

func nameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// refersTo reports whether a parsed rule address names the alias. Live rules
// name a source alias "SRC::<account>::<name>" and a destination alias bare;
// matching the bare name or a "::<name>" suffix, ignoring case, covers both
// and any qualified destination form.
func refersTo(addr, name string) bool {
	// An address is never an alias reference, though an IPv6 literal can end
	// in "::" and a hex word that is also an alias name (2001:db8::cafe).
	if _, err := netip.ParseAddr(addr); err == nil {
		return false
	}
	if _, err := netip.ParsePrefix(addr); err == nil {
		return false
	}
	addr, name = strings.ToLower(addr), strings.ToLower(name)
	return addr == name || strings.HasSuffix(addr, "::"+name)
}

// RuleSet is the deployed rules by index, every one kept: an index two
// rules share holds both (DerivedRole reads neither as verifying a side, and
// scans both for names), and a rule with no parsed form stays for its text.
// Dropping either kind would hide a rule that might deny an alias.
type RuleSet map[int][]ACLRule

// RulesByIndex indexes deployed rules for DerivedRole.
func RulesByIndex(rules []ACLRule) RuleSet {
	m := make(RuleSet, len(rules))
	for _, r := range rules {
		m[r.Index] = append(m[r.Index], r)
	}
	return m
}

// sideOf describes a role for messages.
func sideOf(r Role) string {
	switch r {
	case RoleDeny:
		return "as the source of a deny rule (own-space checked)"
	case RoleDestination:
		return "only as a destination: the addresses a rule protects (not own-space checked)"
	}
	return "as the source of a permit rule (not own-space checked)"
}

// namedOutside reports whether a deployed rule names the alias at an index
// outside prodRules. The alias list (prodRules) and the rules are separate
// reads, and a deployment can land between them: such a rule might deny the
// alias, so its side can't be verified.
func namedOutside(name string, prodRules []int, rules RuleSet) bool {
	for idx, at := range rules {
		if slices.Contains(prodRules, idx) {
			continue
		}
		for _, r := range at {
			if mentions(r.Source, name) || mentions(r.Destination, name) || mentions(r.Text, name) {
				return true
			}
		}
	}
	return false
}
