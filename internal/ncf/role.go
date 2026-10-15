package ncf

import "strings"

// Role sources, as a plan reports them.
const (
	RoleFromRules = "rules" // derived from the deployed ACL rules
	RoleFromFile  = "file"  // no deployed rule references the alias; the file's role stands
)

// DerivedRole says which side of the firewall the deployed rules put an
// alias on. It is deny when any deployed deny rule uses the alias as its
// source, allow when the alias is referenced otherwise (a permit rule, or
// only as a destination), and unknown (ok false) when no deployed rule
// references it.
func DerivedRole(name string, prodRules []int, rules map[int]ACLRule) (Role, bool) {
	referenced := false
	for _, idx := range prodRules {
		r, ok := rules[idx]
		if !ok {
			continue
		}
		referenced = true
		if strings.EqualFold(r.Action, "deny") && refersTo(r.Source, name) {
			return RoleDeny, true
		}
	}
	if !referenced {
		return "", false
	}
	return RoleAllow, true
}

// refersTo reports whether a parsed rule address names the alias. Live rules
// name a source alias "SRC::<account>::<name>" and a destination alias bare;
// matching the bare name or a "::<name>" suffix covers both and any
// qualified destination form.
func refersTo(addr, name string) bool {
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
