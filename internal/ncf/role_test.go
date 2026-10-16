package ncf

import "testing"

func TestRefersTo(t *testing.T) {
	for addr, want := range map[string]bool{
		"block-v4":                       true,
		"SRC::A-EXAMPLE::block-v4":       true,
		"DST::A-EXAMPLE::block-v4":       true,
		"SRC::A-EXAMPLE::block-v4-extra": false,
		"SRC::A-EXAMPLE::other-block-v4": false,
		"block-v4-old":                   false,
		"any":                            false,
	} {
		if got := refersTo(addr, "block-v4"); got != want {
			t.Errorf("refersTo(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestDerivedRole(t *testing.T) {
	rules := RulesByIndex([]ACLRule{
		{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"},
		{Index: 2, Action: "permit", Source: "SRC::A-EXAMPLE::trusted", Destination: "protected-dst"},
		{Index: 3, Action: "DENY", Source: "SRC::A-EXAMPLE::trusted", Destination: "any"},
		{Index: 4, Action: "deny", Source: "SRC:A-EXAMPLE:block-v4", Destination: "any"},
		{Index: 5, Action: "deny", Source: "SRC:A-EXAMPLE:block-v4", Destination: "block-v4"},
		{Index: 6, Action: "permit", Source: "SRC::A-EXAMPLE::partner", Destination: "any"},
	})
	tests := []struct {
		name    string
		indexes []int
		want    Role
		ok      bool
	}{
		{"block-v4", []int{1}, RoleDeny, true},
		{"protected-dst", []int{1, 2}, RoleDestination, true}, // destination only: where the rules apply
		{"partner", []int{6}, RoleAllow, true},
		// Rule 3 denies trusted but isn't among its indexes (a deployment
		// between the reads): unverified, not the allow rule 2 alone says.
		{"trusted", []int{2}, "", false},
		{"trusted", []int{2, 3}, RoleDeny, true}, // any deny-source use makes it deny
		{"unused", nil, "", false},
		{"block-v4", []int{9}, "", false}, // index not in the deployed version
		// An index that resolves to a rule not naming the alias in a known
		// form is unknown, never allow: that would switch checks off.
		{"block-v4", []int{4}, "", false},
		{"BLOCK-V4", []int{1}, RoleDeny, true}, // case-insensitive
		// A recognised destination must not mask a deny source in a form we
		// don't recognise.
		{"block-v4", []int{5}, "", false},
	}
	for _, tt := range tests {
		got, ok := DerivedRole(tt.name, tt.indexes, rules)
		if got != tt.want || ok != tt.ok {
			t.Errorf("DerivedRole(%s, %v) = %q, %v; want %q, %v", tt.name, tt.indexes, got, ok, tt.want, tt.ok)
		}
	}
}

func TestMentionsIsWholeName(t *testing.T) {
	for addr, want := range map[string]bool{
		"SRC::A-EXAMPLE::edge-block": false, // "edge" is part of a longer name
		"SRC:A-EXAMPLE:edge":         true,  // an unrecognised form of the whole name
		"edge":                       true,
		"edgex edge":                 true,
		"A-EDGE-X::other":            false,
	} {
		if got := mentions(addr, "edge"); got != want {
			t.Errorf("mentions(%q, edge) = %v, want %v", addr, got, want)
		}
	}
	// The round-11 case: a destination alias whose name is part of the
	// source alias's name in its own rule derives destination, not unknown.
	rules := RulesByIndex([]ACLRule{{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::edge-block", Destination: "edge"}})
	if r, ok := DerivedRole("edge", []int{1}, rules); r != RoleDestination || !ok {
		t.Errorf("DerivedRole(edge) = %q, %v; want destination", r, ok)
	}
}

// A rule the alias is used by but that isn't in the rule map (no parsed
// details) could be a deny: the side is unverified, not derived from the
// rules that are readable. Duplicated indexes are unknown the same way.
func TestDerivedRoleNeedsEveryRule(t *testing.T) {
	permit := ACLRule{Index: 1, Action: "permit", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}
	if role, ok := DerivedRole("block-v4", []int{1, 2}, RulesByIndex([]ACLRule{permit})); ok {
		t.Errorf("rule 2 missing: derived %s", role)
	}
	deny := ACLRule{Index: 1, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"}
	if role, ok := DerivedRole("block-v4", []int{1}, RulesByIndex([]ACLRule{deny, permit})); ok {
		t.Errorf("index 1 duplicated: derived %s", role)
	}
	if role, ok := DerivedRole("block-v4", []int{1}, RulesByIndex([]ACLRule{permit})); !ok || role != RoleAllow {
		t.Errorf("every rule readable: %s %v", role, ok)
	}
}

// The alias list's rule indexes and the deployed rules come from separate
// reads: a deployed rule that names the alias but isn't among its indexes
// (a deployment between the reads) leaves the side unverified.
func TestDerivedRoleSeesUnlistedRules(t *testing.T) {
	rules := RulesByIndex([]ACLRule{
		{Index: 1, Action: "permit", Source: "SRC::A-EXAMPLE::block-v4", Destination: "any"},
		{Index: 2, Action: "deny", Source: "SRC::A-EXAMPLE::block-v4", Destination: "protected-dst"},
	})
	if role, ok := DerivedRole("block-v4", []int{1}, rules); ok {
		t.Errorf("deny rule 2 unlisted: derived %s", role)
	}
	other := RulesByIndex([]ACLRule{
		{Index: 1, Action: "permit", Source: "SRC::A-EXAMPLE::block-v4", Destination: "any"},
		{Index: 2, Action: "deny", Source: "SRC::A-EXAMPLE::other", Destination: "any"},
	})
	if role, ok := DerivedRole("block-v4", []int{1}, other); !ok || role != RoleAllow {
		t.Errorf("an unlisted rule about another alias: %s %v", role, ok)
	}
}
