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
	})
	tests := []struct {
		name    string
		indexes []int
		want    Role
		ok      bool
	}{
		{"block-v4", []int{1}, RoleDeny, true},
		{"protected-dst", []int{1, 2}, RoleAllow, true}, // destination only
		{"trusted", []int{2}, RoleAllow, true},
		{"trusted", []int{2, 3}, RoleDeny, true}, // any deny-source use makes it deny
		{"unused", nil, "", false},
		{"block-v4", []int{9}, "", false}, // index not in the deployed version
		// An index that resolves to a rule not naming the alias in a known
		// form is unknown, never allow: that would switch checks off.
		{"block-v4", []int{4}, "", false},
		{"BLOCK-V4", []int{1}, RoleDeny, true}, // case-insensitive
	}
	for _, tt := range tests {
		got, ok := DerivedRole(tt.name, tt.indexes, rules)
		if got != tt.want || ok != tt.ok {
			t.Errorf("DerivedRole(%s, %v) = %q, %v; want %q, %v", tt.name, tt.indexes, got, ok, tt.want, tt.ok)
		}
	}
}
