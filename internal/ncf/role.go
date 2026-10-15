package ncf

import "strings"

// Role sources, as a plan reports them.
const (
	RoleFromRules = "rules" // derived from the deployed ACL rules
	RoleFromFile  = "file"  // no deployed rule names the alias; the file's role stands
)

// DerivedRole says which side of the firewall the deployed rules put an
// alias on. It is deny when any deployed deny rule names the alias as its
// source, and allow when rules name it only otherwise (a permit rule's
// source, or a destination). It is unknown (ok false) unless some rule at
// one of the alias's indexes actually names it: a rule in an address form
// this code doesn't recognise must not turn own-space checks off.
func DerivedRole(name string, prodRules []int, rules map[int]ACLRule) (Role, bool) {
	named := false
	for _, idx := range prodRules {
		r, ok := rules[idx]
		if !ok {
			continue
		}
		src, dst := refersTo(r.Source, name), refersTo(r.Destination, name)
		if !src && !dst {
			continue
		}
		named = true
		if src && strings.EqualFold(r.Action, "deny") {
			return RoleDeny, true
		}
	}
	if !named {
		return "", false
	}
	return RoleAllow, true
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
