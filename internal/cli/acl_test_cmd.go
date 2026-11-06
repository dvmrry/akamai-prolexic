package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

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
			packets, err := o.packets(cmd)
			if err != nil {
				return nil, err
			}
			return output.Doc(a.ops().ACLTest(ctx, ops.ACLTestInput{Version: o.version, Packets: packets}))
		}),
	}
	f := cmd.Flags()
	f.IntVar(&o.version, "version", 0, "ACL version number (default: the version in production)")
	f.StringVar(&o.file, "packets", "", "JSON array of up to 5 packets in the analyzer's shape (instead of the packet flags)")
	f.StringVar(&o.src, "src", "", "source IP address")
	f.StringVar(&o.dst, "dst", "", "destination IP address")
	f.StringVar(&o.proto, "proto", "ip", "protocol: "+strings.Join(ncfapi.AnalyzerProtocols, ", "))
	f.IntVar(&o.sport, "sport", 0, "source port (tcp, udp)")
	f.IntVar(&o.dport, "dport", 0, "destination port (tcp, udp)")
	listVar(f, &o.flags, "flags", "TCP flags present, comma-separated: "+strings.Join(ncfapi.AnalyzerTCPFlags, ", "))
	f.IntVar(&o.ttl, "ttl", 0, "IP time to live, 1-255")
	f.IntVar(&o.length, "length", 0, "packet length in bytes")
	f.BoolVar(&o.established, "established", false, "the packet belongs to an established TCP connection")
	f.BoolVar(&o.fragment, "fragment", false, "the packet is an IP fragment")
	f.IntVar(&o.icmpType, "icmp-type", 0, "ICMP type (icmp)")
	f.IntVar(&o.icmpCode, "icmp-code", 0, "ICMP code (icmp)")
	return cmd
}

// packets is the packets the flags describe: those of --packets, or the
// single one the packet flags build.
func (o aclTestFlags) packets(cmd *cobra.Command) ([]ncfapi.PacketTest, error) {
	if o.file == "" {
		return packetsFromFlags(cmd, o)
	}
	for _, n := range packetFlagNames {
		if cmd.Flags().Changed(n) {
			return nil, apperr.New(apperr.Usage, "--packets and --%s cannot be combined", n)
		}
	}
	return packetsFromFile(o.file)
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
