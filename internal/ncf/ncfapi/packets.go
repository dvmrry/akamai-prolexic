package ncfapi

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// The analyzer's limits.
const (
	MaxAnalyzerPackets = 5
	MaxAnalyzerRules   = 500
)

var (
	// AnalyzerProtocols are the protocols a packet can name.
	AnalyzerProtocols = []string{"ip", "ipv4", "ipv6", "icmp", "igmp", "ipinip", "tcp", "igrp", "udp", "gre", "esp", "ahp", "eigrp", "ospf", "nos", "pim"}
	// AnalyzerTCPFlags are the TCP flags a packet can carry.
	AnalyzerTCPFlags = []string{"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}
)

// Packets is a packet list the analyzer accepts: 1 to MaxAnalyzerPackets
// packets with unique ids, each valid for its protocol, all of one IP
// version. Only ParsePackets makes one, so AnalyzeACL never sends a list that
// wasn't checked, whichever front built it.
type Packets struct {
	list      []PacketTest
	ipVersion string
}

// List returns the packets, as sent (with their ids).
func (p Packets) List() []PacketTest { return slices.Clone(p.list) }

// IPVersion is the packets' shared IP version: V4 or V6.
func (p Packets) IPVersion() string { return p.ipVersion }

// ParsePackets checks ps against the analyzer's rules and names unnamed
// packets p1, p2, ... in order. Errors are usage errors naming the packet.
func ParsePackets(ps []PacketTest) (Packets, error) {
	if len(ps) == 0 {
		return Packets{}, apperr.New(apperr.Usage, "no packets to test")
	}
	if len(ps) > MaxAnalyzerPackets {
		return Packets{}, apperr.New(apperr.Usage, "%d packets: the analyzer takes at most %d", len(ps), MaxAnalyzerPackets)
	}
	out := Packets{list: slices.Clone(ps)}
	seen := map[string]bool{}
	for i := range out.list {
		p := &out.list[i]
		p.PacketID = cmp.Or(p.PacketID, "p"+strconv.Itoa(i+1))
		if seen[p.PacketID] {
			return Packets{}, apperr.New(apperr.Usage, "packet id %q is used twice", p.PacketID)
		}
		seen[p.PacketID] = true
		v, err := checkPacket(*p)
		if err != nil {
			return Packets{}, err
		}
		if out.ipVersion != "" && v != out.ipVersion {
			return Packets{}, apperr.New(apperr.Usage, "packets mix IPv4 and IPv6; test them separately")
		}
		out.ipVersion = v
	}
	return out, nil
}

func inRange(v *int, lo, hi int) bool { return v == nil || (*v >= lo && *v <= hi) }

// checkPacket checks one packet against the analyzer's rules and returns its
// IP version (V4 or V6).
func checkPacket(p PacketTest) (string, error) {
	bad := func(format string, args ...any) (string, error) {
		return "", apperr.New(apperr.Usage, "packet %s: "+format, append([]any{p.PacketID}, args...)...)
	}
	src, err := netip.ParseAddr(p.SrcIP)
	if err != nil {
		return bad("source %q is not an IP address", p.SrcIP)
	}
	dst, err := netip.ParseAddr(p.DstIP)
	if err != nil {
		return bad("destination %q is not an IP address", p.DstIP)
	}
	if src.Is4() != dst.Is4() {
		return bad("source and destination are different IP versions")
	}
	if !slices.Contains(AnalyzerProtocols, p.Protocol) {
		return bad("protocol %q is not one of %s", p.Protocol, strings.Join(AnalyzerProtocols, ", "))
	}
	for _, c := range []struct {
		name string
		v    *int
		lo   int
		hi   int
	}{{"source port", p.SrcPort, 0, 65535}, {"destination port", p.DstPort, 0, 65535}, {"ttl", p.TTL, 1, 255},
		{"length", p.PacketLength, 1, 1<<31 - 1}, {"ICMP type", p.ICMPType, 0, 255}, {"ICMP code", p.ICMPCode, 0, 255}} {
		if !inRange(c.v, c.lo, c.hi) {
			return bad("%s %d is outside %d-%d", c.name, *c.v, c.lo, c.hi)
		}
	}
	if (p.SrcPort != nil || p.DstPort != nil) && p.Protocol != "tcp" && p.Protocol != "udp" {
		return bad("ports apply to tcp and udp only")
	}
	if len(p.TCPFlags) > 0 && p.Protocol != "tcp" {
		return bad("TCP flags apply to tcp only")
	}
	for _, fl := range p.TCPFlags {
		if !slices.Contains(AnalyzerTCPFlags, fl) {
			return bad("TCP flag %q is not one of %s", fl, strings.Join(AnalyzerTCPFlags, ", "))
		}
	}
	if (p.ICMPType != nil || p.ICMPCode != nil) && p.Protocol != "icmp" {
		return bad("ICMP type and code apply to icmp only")
	}
	if p.Established && p.Protocol != "tcp" {
		return bad("established applies to tcp only")
	}
	if p.Established && p.IsFragment {
		return bad("a packet cannot be both established and a fragment")
	}
	if src.Is4() {
		return "V4", nil
	}
	return "V6", nil
}
