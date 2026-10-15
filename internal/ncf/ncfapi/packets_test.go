package ncfapi

import (
	"context"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

func port(n int) *int { return &n }

func TestParsePackets(t *testing.T) {
	tcp := PacketTest{Protocol: "tcp", SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: port(443)}
	ok, err := ParsePackets([]PacketTest{tcp, {PacketID: "dns", Protocol: "udp", SrcIP: "192.0.2.2", DstIP: "198.51.100.2", DstPort: port(53)}})
	if err != nil || ok.IPVersion() != "V4" || ok.List()[0].PacketID != "p1" || ok.List()[1].PacketID != "dns" {
		t.Fatalf("packets = %+v, err = %v", ok, err)
	}
	six := func(p PacketTest) []PacketTest { return []PacketTest{p, p, p, p, p, p} }
	for name, tt := range map[string]struct {
		ps   []PacketTest
		want string
	}{
		"none":         {nil, "no packets"},
		"six":          {six(tcp), "at most 5"},
		"duplicate id": {[]PacketTest{{PacketID: "a", Protocol: "ip", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}, {PacketID: "a", Protocol: "ip", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}}, "used twice"},
		"bad address":  {[]PacketTest{{Protocol: "ip", SrcIP: "nope", DstIP: "192.0.2.2"}}, "not an IP address"},
		"mixed in one": {[]PacketTest{{Protocol: "ip", SrcIP: "192.0.2.1", DstIP: "2001:db8::1"}}, "different IP versions"},
		"mixed across": {[]PacketTest{tcp, {Protocol: "ipv6", SrcIP: "2001:db8::1", DstIP: "2001:db8::2"}}, "mix IPv4 and IPv6"},
		"protocol":     {[]PacketTest{{Protocol: "smtp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}}, "not one of"},
		"port range":   {[]PacketTest{{Protocol: "tcp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: port(70000)}}, "outside"},
		"port on icmp": {[]PacketTest{{Protocol: "icmp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", DstPort: port(1)}}, "tcp and udp only"},
		"est and frag": {[]PacketTest{{Protocol: "tcp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Established: true, IsFragment: true}}, "both established"},
		"flag on udp":  {[]PacketTest{{Protocol: "udp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TCPFlags: []string{"syn"}}}, "tcp only"},
		"unknown flag": {[]PacketTest{{Protocol: "tcp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", TCPFlags: []string{"xmas"}}}, "not one of"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePackets(tt.ps)
			if apperr.KindOf(err) != apperr.Usage || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a usage error containing %q", err, tt.want)
			}
		})
	}
}

// AnalyzeACL refuses packets that didn't come from ParsePackets, and rules
// that don't match them, before sending anything.
func TestAnalyzeACLRefusesUncheckedInput(t *testing.T) {
	s := &V2{} // no client: a refusal must come before any request
	ok, _ := ParsePackets([]PacketTest{{Protocol: "ip", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}})
	rule := AnalyzerRule{Index: 1, ACLText: "permit ip any any", IPVersion: "V4"}
	for name, call := range map[string]func() error{
		"zero Packets": func() error {
			_, err := s.AnalyzeACL(context.Background(), []AnalyzerRule{rule}, Packets{})
			return err
		},
		"no rules": func() error { _, err := s.AnalyzeACL(context.Background(), nil, ok); return err },
		"wrong version": func() error {
			r := rule
			r.IPVersion = "V6"
			_, err := s.AnalyzeACL(context.Background(), []AnalyzerRule{r}, ok)
			return err
		},
		"bad index": func() error {
			r := rule
			r.Index = 2
			_, err := s.AnalyzeACL(context.Background(), []AnalyzerRule{r}, ok)
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
