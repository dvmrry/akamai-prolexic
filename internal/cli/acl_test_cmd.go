package cli

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

const (
	maxAnalyzerPackets = 5
	maxAnalyzerRules   = 500
)

var (
	analyzerProtocols = []string{"ip", "ipv4", "ipv6", "icmp", "igmp", "ipinip", "tcp", "igrp", "udp", "gre", "esp", "ahp", "eigrp", "ospf", "nos", "pim"}
	analyzerTCPFlags  = []string{"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}
)

// ACLTestRule is the rule that decided a packet, by its index in the tested
// ACL version (not the renumbered one the analyzer saw).
type ACLTestRule struct {
	Index   int    `json:"index" doc:"The rule's index in the ACL version."`
	ACLText string `json:"aclText"`
}

// ACLTestResult is one packet's verdict.
type ACLTestResult struct {
	Packet         ncfapi.PacketTest `json:"packet" doc:"As sent, with its packetId."`
	Decision       string            `json:"decision" doc:"ALLOW or DENY."`
	ImplicitPermit bool              `json:"implicitPermit" doc:"No rule matched; the default permit applied."`
	Rule           *ACLTestRule      `json:"rule" doc:"The first rule that matched; null on an implicit permit."`
}

// ACLTestDoc is the outcome of testing packets against an ACL version.
type ACLTestDoc struct {
	output.Header
	Version     int                    `json:"version" doc:"The ACL version tested."`
	Production  bool                   `json:"production" doc:"That version is in production."`
	IPVersion   string                 `json:"ipVersion" doc:"V4 or V6: only the version's rules of this family were tested."`
	RulesTested int                    `json:"rulesTested"`
	Results     []ACLTestResult        `json:"results" doc:"One per packet, in the order given."`
	Summary     ncfapi.AnalyzerSummary `json:"summary"`
}

func (*ACLTestDoc) SchemaID() string { return "prolexic.acl-test.v1" }

func (d *ACLTestDoc) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "ACL version %d", d.Version)
	if d.Production {
		fmt.Fprint(w, " (production)")
	}
	fmt.Fprintf(w, ", %d %s rules tested\n", d.RulesTested, d.IPVersion)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKET\tFLOW\tVERDICT\tRULE")
	for _, r := range d.Results {
		rule := "implicit permit"
		if r.Rule != nil {
			rule = fmt.Sprintf("#%d %s", r.Rule.Index, r.Rule.ACLText)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Packet.PacketID, packetFlow(r.Packet), r.Decision, rule)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%d allowed, %d denied\n", d.Summary.Allowed, d.Summary.Denied)
	return err
}

func packetFlow(p ncfapi.PacketTest) string {
	end := func(ip string, port *int) string {
		if port == nil {
			return ip
		}
		if strings.Contains(ip, ":") {
			return "[" + ip + "]:" + strconv.Itoa(*port)
		}
		return ip + ":" + strconv.Itoa(*port)
	}
	return fmt.Sprintf("%s %s -> %s", p.Protocol, end(p.SrcIP, p.SrcPort), end(p.DstIP, p.DstPort))
}

type aclTestFlags struct {
	version                   int
	file                      string
	src, dst, proto           string
	sport, dport, ttl, length int
	flags                     []string
	established, fragment     bool
	icmpType, icmpCode        int
}

func newACLTestCmd(a *app) *cobra.Command {
	var o aclTestFlags
	var cmd *cobra.Command
	cmd = &cobra.Command{
		Use:   "test",
		Short: "test packets against an ACL version's rules (nothing is changed)",
		Long: "Evaluates an ACL version's rules (default: production) against simulated packets with the ACL analyzer and reports each packet's verdict and the rule that decided it. " +
			"The rules tested are those of the packets' IP family, renumbered from 1 for the analyzer and mapped back to their real indexes in the output. " +
			"Give one packet with --src and --dst, or up to 5 with --packets FILE (a JSON array of packets in the analyzer's shape).",
		Example: "  prolexic acl test --src 192.0.2.10 --dst 198.51.100.5 --proto tcp --dport 443\n  prolexic acl test --version 8 --packets packets.json",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return aclTest(ctx, a, cmd, o)
		}),
	}
	f := cmd.Flags()
	f.IntVar(&o.version, "version", 0, "ACL version number (default: the version in production)")
	f.StringVar(&o.file, "packets", "", "JSON array of up to 5 packets in the analyzer's shape (instead of the packet flags)")
	f.StringVar(&o.src, "src", "", "source IP address")
	f.StringVar(&o.dst, "dst", "", "destination IP address")
	f.StringVar(&o.proto, "proto", "ip", "protocol: "+strings.Join(analyzerProtocols, ", "))
	f.IntVar(&o.sport, "sport", 0, "source port (tcp, udp)")
	f.IntVar(&o.dport, "dport", 0, "destination port (tcp, udp)")
	listVar(f, &o.flags, "flags", "TCP flags present, comma-separated: "+strings.Join(analyzerTCPFlags, ", "))
	f.IntVar(&o.ttl, "ttl", 0, "IP time to live, 1-255")
	f.IntVar(&o.length, "length", 0, "packet length in bytes")
	f.BoolVar(&o.established, "established", false, "the packet belongs to an established TCP connection")
	f.BoolVar(&o.fragment, "fragment", false, "the packet is an IP fragment")
	f.IntVar(&o.icmpType, "icmp-type", 0, "ICMP type (icmp)")
	f.IntVar(&o.icmpCode, "icmp-code", 0, "ICMP code (icmp)")
	return cmd
}

var packetFlagNames = []string{"src", "dst", "proto", "sport", "dport", "flags", "ttl", "length", "established", "fragment", "icmp-type", "icmp-code"}

// packetsFromFlags builds the single packet the flags describe.
func packetsFromFlags(cmd *cobra.Command, o aclTestFlags) ([]ncfapi.PacketTest, error) {
	if o.src == "" || o.dst == "" {
		return nil, apperr.New(apperr.Usage, "--src and --dst are required (or --packets FILE)")
	}
	p := ncfapi.PacketTest{Protocol: o.proto, SrcIP: o.src, DstIP: o.dst, TCPFlags: o.flags,
		Established: o.established, IsFragment: o.fragment}
	set := func(name string, v int) *int {
		if cmd.Flags().Changed(name) {
			return &v
		}
		return nil
	}
	p.SrcPort, p.DstPort = set("sport", o.sport), set("dport", o.dport)
	p.TTL, p.PacketLength = set("ttl", o.ttl), set("length", o.length)
	p.ICMPType, p.ICMPCode = set("icmp-type", o.icmpType), set("icmp-code", o.icmpCode)
	return []ncfapi.PacketTest{p}, nil
}

// packetsFromFile strictly decodes a JSON array of packets.
func packetsFromFile(path string) ([]ncfapi.PacketTest, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, apperr.New(apperr.NotFound, "no packets file %s", path)
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "read %s", path)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var ps []ncfapi.PacketTest
	if err := dec.Decode(&ps); err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "%s: not a JSON array of packets", path)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, apperr.New(apperr.Usage, "%s: data after the packets array", path)
	}
	return ps, nil
}

func inRange(v *int, lo, hi int) bool { return v == nil || (*v >= lo && *v <= hi) }

// validatePacket checks one packet against the analyzer's rules and returns
// its IP version (V4 or V6).
func validatePacket(p ncfapi.PacketTest) (string, error) {
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
	if !slices.Contains(analyzerProtocols, p.Protocol) {
		return bad("protocol %q is not one of %s", p.Protocol, strings.Join(analyzerProtocols, ", "))
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
		if !slices.Contains(analyzerTCPFlags, fl) {
			return bad("TCP flag %q is not one of %s", fl, strings.Join(analyzerTCPFlags, ", "))
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

// preparePackets validates the packets, names the unnamed ones p1.., and
// returns their shared IP version.
func preparePackets(ps []ncfapi.PacketTest) (string, error) {
	if len(ps) == 0 {
		return "", apperr.New(apperr.Usage, "no packets to test")
	}
	if len(ps) > maxAnalyzerPackets {
		return "", apperr.New(apperr.Usage, "%d packets: the analyzer takes at most %d", len(ps), maxAnalyzerPackets)
	}
	seen := map[string]bool{}
	version := ""
	for i := range ps {
		ps[i].PacketID = cmp.Or(ps[i].PacketID, "p"+strconv.Itoa(i+1))
		if seen[ps[i].PacketID] {
			return "", apperr.New(apperr.Usage, "packet id %q is used twice", ps[i].PacketID)
		}
		seen[ps[i].PacketID] = true
		v, err := validatePacket(ps[i])
		if err != nil {
			return "", err
		}
		if version != "" && v != version {
			return "", apperr.New(apperr.Usage, "packets mix IPv4 and IPv6; test them separately")
		}
		version = v
	}
	return version, nil
}

func aclTest(ctx context.Context, a *app, cmd *cobra.Command, o aclTestFlags) (output.Document, error) {
	if o.version < 0 {
		return nil, apperr.New(apperr.Usage, "--version must be positive")
	}
	var packets []ncfapi.PacketTest
	var err error
	if o.file != "" {
		for _, n := range packetFlagNames {
			if cmd.Flags().Changed(n) {
				return nil, apperr.New(apperr.Usage, "--packets and --%s cannot be combined", n)
			}
		}
		packets, err = packetsFromFile(o.file)
	} else {
		packets, err = packetsFromFlags(cmd, o)
	}
	if err != nil {
		return nil, err
	}
	ipVersion, err := preparePackets(packets)
	if err != nil {
		return nil, err
	}

	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	sets, err := api.DeploymentSets(ctx)
	if err != nil {
		return nil, err
	}
	prod, perr := ncfapi.ProductionVersion(sets)
	v := o.version
	if v == 0 {
		if perr != nil {
			return nil, perr
		}
		v = prod
	}
	got, err := api.ACLVersion(ctx, v)
	if err != nil {
		return nil, err
	}

	// The analyzer takes one IP version, indexes from 1. Rules without a
	// version (remarks) ride along with whichever family is tested.
	details := slices.Clone(got.Rules)
	slices.SortStableFunc(details, func(x, y ncfapi.ACLRuleDetail) int { return cmp.Compare(x.Index, y.Index) })
	var rules []ncfapi.AnalyzerRule
	original := map[int]ncfapi.ACLRuleDetail{}
	for _, r := range details {
		row := ruleRow(r)
		rv := strings.ToUpper(row.IPVersion)
		if (rv != "" && rv != ipVersion) || r.ACLText == "" {
			continue
		}
		rules = append(rules, ncfapi.AnalyzerRule{Index: len(rules) + 1, ACLText: r.ACLText, IPVersion: ipVersion, Comment: r.Comment})
		original[len(rules)] = r
	}
	if len(rules) == 0 {
		return nil, apperr.New(apperr.NotFound, "ACL version %d has no %s rules to test", v, ipVersion)
	}
	if len(rules) > maxAnalyzerRules {
		return nil, apperr.New(apperr.Validation, "ACL version %d has %d %s rules: the analyzer takes at most %d", v, len(rules), ipVersion, maxAnalyzerRules)
	}

	resp, err := api.AnalyzeACL(ctx, rules, packets)
	if err != nil {
		return nil, err
	}
	if len(resp.Results) != len(packets) {
		return nil, apperr.New(apperr.Upstream, "the analyzer returned %d results for %d packets", len(resp.Results), len(packets))
	}
	doc := &ACLTestDoc{Version: cmp.Or(got.Version, v), Production: perr == nil && v == prod, IPVersion: ipVersion,
		RulesTested: len(rules), Results: make([]ACLTestResult, 0, len(packets)), Summary: resp.Summary}
	for i, r := range resp.Results {
		res := ACLTestResult{Packet: packets[i], Decision: r.Decision, ImplicitPermit: r.ImplicitPermit}
		if r.MatchedRule != nil {
			orig, ok := original[r.MatchedRule.Index]
			if !ok {
				return nil, apperr.New(apperr.Upstream, "the analyzer matched rule %d, which was not sent", r.MatchedRule.Index)
			}
			res.Rule = &ACLTestRule{Index: orig.Index, ACLText: cmp.Or(orig.ACLText, r.MatchedRule.ACLText)}
		}
		doc.Results = append(doc.Results, res)
	}
	return doc, nil
}
