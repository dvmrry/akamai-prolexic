package ncf

import "strings"

// Role sources, as a plan reports them.
const (
	RoleFromRules = "rules" // derived from the deployed ACL rules
	RoleFromFile  = "file"  // no deployed rule references the alias; the file's role stands
	// RoleUnverified: deployed rules reference the alias but its side can't
	// be read, so it is checked as deny whatever the file says.
	RoleUnverified = "unverified"
)

// DerivedRole says which side of the firewall the deployed rules put an
// alias on. It is deny when any deployed deny rule names the alias as its
// source, and allow when rules name it only otherwise (a permit rule's
// source, or a destination). It is unknown (ok false) unless some rule at
// one of the alias's indexes actually names it: a rule in an address form
// this code doesn't recognise must not turn own-space checks off.
func DerivedRole(name string, prodRules []int, rules map[int]ACLRule) (Role, bool) {
	named, unknownAction := false, false
	for _, idx := range prodRules {
		r, ok := rules[idx]
		if !ok {
			continue
		}
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
		}
	}
	if unknownAction || !named {
		return "", false
	}
	return RoleAllow, true
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
	addr, name = strings.ToLower(addr), strings.ToLower(name)
	return addr == name || strings.HasSuffix(addr, "::"+name)
}

// RulesByIndex indexes deployed rules for DerivedRole.
func RulesByIndex(rules []ACLRule) map[int]ACLRule {
	m := make(map[int]ACLRule, len(rules))
	for _, r := range rules {
		m[r.Index] = r
	}
	return m
}

// sideOf describes a role for messages.
func sideOf(r Role) string {
	if r == RoleDeny {
		return "as the source of a deny rule (own-space checked)"
	}
	return "only as a destination or a permit-side source (not own-space checked)"
}
