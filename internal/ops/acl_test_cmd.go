package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
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

// ACLTestInput is a set of simulated packets and the ACL version to test them against.
type ACLTestInput struct {
	Version int                 // the ACL version number; zero means the version in production
	Packets []ncfapi.PacketTest // 1 to 5 packets, all of one IP family
}

// ACLTest evaluates the version's rules against the packets with the ACL
// analyzer. Nothing is changed.
func (r *Runtime) ACLTest(ctx context.Context, in ACLTestInput) (*ACLTestDoc, error) {
	if in.Version < 0 {
		return nil, apperr.New(apperr.Usage, "the ACL version must not be negative")
	}
	parsed, err := ncfapi.ParsePackets(in.Packets)
	if err != nil {
		return nil, err
	}
	packets, ipVersion := parsed.List(), parsed.IPVersion()

	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	sets, err := api.DeploymentSets(ctx)
	if err != nil {
		return nil, err
	}
	prod, perr := ncfapi.ProductionVersion(sets)
	v := in.Version
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
	if len(rules) > ncfapi.MaxAnalyzerRules {
		return nil, apperr.New(apperr.Validation, "ACL version %d has %d %s rules: the analyzer takes at most %d", v, len(rules), ipVersion, ncfapi.MaxAnalyzerRules)
	}

	resp, err := api.AnalyzeACL(ctx, rules, parsed)
	if err != nil {
		return nil, err
	}
	// Join results to packets on packetId, never on position: a verdict on the
	// wrong packet would answer "is this flow denied?" wrongly and silently.
	byID := make(map[string]ncfapi.AnalyzerResult, len(resp.Results))
	for _, r := range resp.Results {
		if _, dup := byID[r.PacketID]; dup {
			return nil, apperr.New(apperr.Upstream, "the analyzer returned two results for packet %q", r.PacketID)
		}
		byID[r.PacketID] = r
	}
	for _, p := range packets {
		if _, ok := byID[p.PacketID]; !ok {
			return nil, apperr.New(apperr.Upstream, "the analyzer returned no result for packet %q", p.PacketID)
		}
	}
	if len(byID) != len(packets) {
		return nil, apperr.New(apperr.Upstream, "the analyzer returned results for packets that were not sent")
	}
	doc := &ACLTestDoc{Version: cmp.Or(got.Version, v), Production: perr == nil && v == prod, IPVersion: ipVersion,
		RulesTested: len(rules), Results: make([]ACLTestResult, 0, len(packets)), Summary: resp.Summary}
	for _, p := range packets {
		r := byID[p.PacketID]
		res := ACLTestResult{Packet: p, Decision: r.Decision, ImplicitPermit: r.ImplicitPermit}
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
