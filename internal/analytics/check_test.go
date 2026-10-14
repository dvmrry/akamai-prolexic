package analytics

import (
	"net/netip"
	"strings"
	"testing"
)

func sess(customer, dc, router, v4, v6 string) BGPSession {
	return BGPSession{Customer: customer, DataCenter: dc, RouterName: router, CustomerBgpPeerIpv4: v4, CustomerBgpPeerIpv6: v6}
}

func route(customer, prefix, peer string) Route {
	return Route{Customer: customer, Prefix: prefix, CustomerBgpPeerIp: peer}
}

func TestEvaluateCheck(t *testing.T) {
	sessions := []BGPSession{
		sess("example-a", "DC-B", "edge-2", "192.0.2.6", "2001:db8::6"),
		sess("example-a", "DC-A", "edge-1", "192.0.2.14", ""),
		sess("example-b", "DC-A", "edge-9", "192.0.2.22", "2001:db8::16"),
	}
	tests := []struct {
		name      string
		routes    []Route
		prefix    string
		expect    Expect
		sites     []string
		wantCarry string // "customer/dc=bool" of expected sessions, sorted
		wantSkip  int
		wantOff   int
		satisfied bool
	}{
		{
			name:      "v4 present everywhere",
			routes:    []Route{route("example-a", "203.0.113.0/24", "192.0.2.6"), route("example-a", "203.0.113.0/24", "192.0.2.14"), route("example-b", "203.0.113.0/24", "192.0.2.22")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectPresent,
			wantCarry: "example-a/DC-A=true example-a/DC-B=true example-b/DC-A=true",
			satisfied: true,
		},
		{
			name:      "v4 present, one missing",
			routes:    []Route{route("example-a", "203.0.113.0/24", "192.0.2.6"), route("example-b", "203.0.113.0/24", "192.0.2.22")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectPresent,
			wantCarry: "example-a/DC-A=false example-a/DC-B=true example-b/DC-A=true",
			wantOff:   1,
		},
		{
			name:      "v4 absent satisfied",
			routes:    []Route{route("example-a", "198.51.100.0/24", "192.0.2.6")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectAbsent,
			wantCarry: "example-a/DC-A=false example-a/DC-B=false example-b/DC-A=false",
			satisfied: true,
		},
		{
			name:      "v4 absent, still carried on one",
			routes:    []Route{route("example-a", "203.0.113.0/24", "192.0.2.14")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectAbsent,
			wantCarry: "example-a/DC-A=true example-a/DC-B=false example-b/DC-A=false",
			wantOff:   1,
		},
		{
			name:      "v6 skips the session with no v6 peer",
			routes:    []Route{route("example-a", "2001:db8:1::/48", "2001:db8::6"), route("example-b", "2001:db8:1::/48", "2001:db8::16")},
			prefix:    "2001:db8:1::/48",
			expect:    ExpectPresent,
			wantCarry: "example-a/DC-B=true example-b/DC-A=true",
			wantSkip:  1,
			satisfied: true,
		},
		{
			name:      "peer formatting differences",
			routes:    []Route{route("example-a", "2001:db8:1::/48", "2001:db8::0:6"), route("example-b", "2001:DB8:0:0::16", "x")},
			prefix:    "2001:db8:1::/48",
			expect:    ExpectPresent,
			wantCarry: "example-a/DC-B=true example-b/DC-A=false",
			wantSkip:  1,
			wantOff:   1,
		},
		{
			name:      "covering and covered prefixes do not count",
			routes:    []Route{route("example-a", "203.0.113.0/25", "192.0.2.6"), route("example-a", "203.0.113.0/24", "192.0.2.14")},
			prefix:    "203.0.113.0/26",
			expect:    ExpectPresent,
			wantCarry: "example-a/DC-A=false example-a/DC-B=false example-b/DC-A=false",
			wantOff:   3,
		},
		{
			name:      "unmasked route prefix still equals",
			routes:    []Route{route("example-a", "203.0.113.7/24", "192.0.2.6")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectPresent,
			sites:     []string{"DC-B"},
			wantCarry: "example-a/DC-B=true",
			satisfied: true,
		},
		{
			name:      "site filter narrows expected sessions",
			routes:    []Route{route("example-a", "203.0.113.0/24", "192.0.2.6")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectPresent,
			sites:     []string{"DC-B"},
			wantCarry: "example-a/DC-B=true",
			satisfied: true,
		},
		{
			name:      "same peer under another customer does not count",
			routes:    []Route{route("example-b", "203.0.113.0/24", "192.0.2.6")},
			prefix:    "203.0.113.0/24",
			expect:    ExpectPresent,
			sites:     []string{"DC-B"},
			wantCarry: "example-a/DC-B=false",
			wantOff:   1,
		},
		{
			name:   "no expected sessions is never satisfied",
			routes: nil,
			prefix: "203.0.113.0/24",
			expect: ExpectAbsent,
			sites:  []string{"DC-NOWHERE"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tt.prefix)
			res := EvaluateCheck(sessions, tt.routes, p, tt.expect, tt.sites)
			var got []string
			for _, s := range res.Sessions {
				got = append(got, s.Customer+"/"+s.DataCenter+"="+map[bool]string{true: "true", false: "false"}[s.Carried])
			}
			if strings.Join(got, " ") != tt.wantCarry {
				t.Errorf("sessions = %v, want %s", got, tt.wantCarry)
			}
			if len(res.Skipped) != tt.wantSkip || res.Off != tt.wantOff || res.Satisfied() != tt.satisfied {
				t.Errorf("skipped=%d off=%d satisfied=%v, want %d %d %v", len(res.Skipped), res.Off, res.Satisfied(), tt.wantSkip, tt.wantOff, tt.satisfied)
			}
		})
	}
}

func TestEvaluateCheckPeerIsNormalised(t *testing.T) {
	s := []BGPSession{sess("example-a", "DC-A", "edge-1", "", "2001:db8::0:6")}
	res := EvaluateCheck(s, nil, netip.MustParsePrefix("2001:db8:1::/48"), ExpectPresent, nil)
	if len(res.Sessions) != 1 || res.Sessions[0].Peer != "2001:db8::6" {
		t.Errorf("sessions = %+v", res.Sessions)
	}
}

func TestParsePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9/24": "203.0.113.0/24",
		"203.0.113.9":    "203.0.113.9/32",
		"2001:db8::1":    "2001:db8::1/128",
		"2001:db8::1/32": "2001:db8::/32",
	} {
		p, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"", "nope", "203.0.113.0/33", "203.0.113.0/"} {
		if _, err := ParsePrefix(in); err == nil {
			t.Errorf("ParsePrefix(%q) succeeded", in)
		}
	}
}
