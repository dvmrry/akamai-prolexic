package ncfapi

import (
	"context"
	"net/http"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// AnalyzerRule is one rule submitted to the ACL analyzer.
type AnalyzerRule struct {
	Index     int    `json:"index" doc:"Sequential from 1."`
	ACLText   string `json:"aclText"`
	IPVersion string `json:"ipVersion" doc:"V4 or V6."`
	Comment   string `json:"comment,omitempty"`
}

// PacketTest is one simulated packet, in the analyzer's request shape.
type PacketTest struct {
	PacketID     string   `json:"packetId,omitempty" doc:"Generated (p1, p2, ...) when absent."`
	Protocol     string   `json:"protocol"`
	SrcIP        string   `json:"srcIp"`
	DstIP        string   `json:"dstIp"`
	SrcPort      *int     `json:"srcPort,omitempty" doc:"TCP and UDP only."`
	DstPort      *int     `json:"dstPort,omitempty" doc:"TCP and UDP only."`
	TCPFlags     []string `json:"tcpFlags,omitempty" doc:"TCP only: fin, syn, rst, psh, ack, urg, ece, cwr."`
	TTL          *int     `json:"ttl,omitempty" doc:"1-255."`
	PacketLength *int     `json:"packetLength,omitempty" doc:"Total size in bytes."`
	Established  bool     `json:"established,omitempty" doc:"Part of an established TCP connection; excludes isFragment."`
	IsFragment   bool     `json:"isFragment,omitempty" doc:"An IP fragment; excludes established."`
	ICMPType     *int     `json:"icmpType,omitempty" doc:"ICMP only."`
	ICMPCode     *int     `json:"icmpCode,omitempty" doc:"ICMP only."`
}

// AnalyzerMatchedRule is the rule that decided a packet, by the index sent.
type AnalyzerMatchedRule struct {
	Index   int    `json:"index"`
	ACLText string `json:"aclText"`
}

// AnalyzerResult is the verdict for one packet.
type AnalyzerResult struct {
	PacketID       string               `json:"packetId"`
	Decision       string               `json:"decision" doc:"ALLOW or DENY."`
	ImplicitPermit bool                 `json:"implicitPermit" doc:"No rule matched; the default permit applied."`
	MatchedRule    *AnalyzerMatchedRule `json:"matchedRule"`
}

// AnalyzerSummary counts the verdicts.
type AnalyzerSummary struct {
	TotalPackets int `json:"totalPackets"`
	Allowed      int `json:"allowed"`
	Denied       int `json:"denied"`
}

// AnalyzerResponse is the analyzer's answer, as far as the CLI reads it.
type AnalyzerResponse struct {
	AnalysisType    string           `json:"analysisType"`
	ExecutionTimeMs int              `json:"executionTimeMs"`
	Timestamp       string           `json:"timestamp"`
	Results         []AnalyzerResult `json:"results"`
	Summary         AnalyzerSummary  `json:"summary"`
}

// AnalyzeACL evaluates rules against packets without changing anything: the
// POST only queries, so it is marked ReadOnly (retried like a read). A 403 is
// reported as a credentials error that names the likely cause.
func (s *V2) AnalyzeACL(ctx context.Context, rules []AnalyzerRule, packets Packets) (AnalyzerResponse, error) {
	if len(packets.list) == 0 {
		return AnalyzerResponse{}, apperr.New(apperr.Bug, "AnalyzeACL: packets not from ParsePackets")
	}
	if len(rules) == 0 || len(rules) > MaxAnalyzerRules {
		return AnalyzerResponse{}, apperr.New(apperr.Validation, "%d rules: the analyzer takes 1 to %d", len(rules), MaxAnalyzerRules)
	}
	for i, r := range rules {
		if r.Index != i+1 || r.IPVersion != packets.ipVersion {
			return AnalyzerResponse{}, apperr.New(apperr.Bug, "AnalyzeACL: rule %d must have index %d and IP version %s", i, i+1, packets.ipVersion)
		}
	}
	body := struct {
		Rules       []AnalyzerRule `json:"rules"`
		PacketTests []PacketTest   `json:"packetTests"`
	}{rules, packets.list}
	var resp AnalyzerResponse
	err := s.c.Do(ctx, akamai.Request{Method: http.MethodPost, Path: v2Path + "/acls/analyzer/test", JSON: body, ReadOnly: true}, &resp)
	if u := apperr.UpstreamOf(err); u != nil && u.Status == http.StatusForbidden {
		return resp, apperr.Wrap(apperr.Credentials, err, "the ACL analyzer refused these credentials; this endpoint may need a different API grant than the read key has")
	}
	if resp.Results == nil {
		resp.Results = []AnalyzerResult{}
	}
	return resp, err
}
