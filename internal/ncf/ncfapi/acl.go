package ncfapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// ACLVersionInfo is one item of the ACL version list.
type ACLVersionInfo struct {
	Version     int    `json:"version"`
	State       string `json:"state" doc:"CONFIGURATION, DEPLOYED or DEPRECATED."`
	Description string `json:"description,omitempty"`
	RulesCount  int    `json:"rulesCount"`
	CreatedBy   string `json:"createdBy,omitempty"`
	Created     string `json:"created,omitempty" doc:"As the API reports it."`
	UpdatedBy   string `json:"updatedBy,omitempty"`
	Updated     string `json:"updated,omitempty" doc:"As the API reports it."`
}

// ListACLVersions reads every page of the ACL version list.
func (s *V2) ListACLVersions(ctx context.Context) ([]ACLVersionInfo, error) {
	rows, err := getPages[struct {
		Version     int    `json:"version"`
		State       string `json:"state"`
		Description string `json:"description"`
		RulesCount  int    `json:"rulesCount"`
		CreatedBy   string `json:"createdBy"`
		Created     string `json:"createdTimestamp"`
		UpdatedBy   string `json:"updatedBy"`
		Updated     string `json:"updatedTimestamp"`
	}](ctx, s.c, v2Path+"/acls/versions", nil)
	if err != nil {
		return nil, err
	}
	out := make([]ACLVersionInfo, len(rows))
	for i, r := range rows {
		out[i] = ACLVersionInfo{Version: r.Version, State: r.State, Description: r.Description, RulesCount: r.RulesCount,
			CreatedBy: r.CreatedBy, Created: r.Created, UpdatedBy: r.UpdatedBy, Updated: r.Updated}
	}
	return out, nil
}

// Range is an inclusive numeric range as the API sends it.
type Range struct {
	Min *int `json:"min,omitempty"`
	Max *int `json:"max,omitempty"`
}

// Span is an inclusive range with both ends known.
type Span struct{ Min, Max int }

// The full spans: a range covering one of them doesn't restrict.
var (
	AllProtocols = Span{0, 255}
	AllPorts     = Span{0, 65535}
)

// span resolves r against the full span: a missing end takes full's. ok is
// false when r gives no end at all.
func (r *Range) span(full Span) (Span, bool) {
	if r == nil || (r.Min == nil && r.Max == nil) {
		return Span{}, false
	}
	s := full
	if r.Min != nil {
		s.Min = *r.Min
	}
	if r.Max != nil {
		s.Max = *r.Max
	}
	return s, true
}

// PortRange is a TCP or UDP port pair.
type PortRange struct {
	SourcePort      *Range `json:"sourcePort,omitempty"`
	DestinationPort *Range `json:"destinationPort,omitempty"`
}

// SourcePorts is the source port range the rule restricts to; ok is false
// when it doesn't restrict (no range, or all of 0-65535).
func (p *PortRange) SourcePorts() (Span, bool) {
	if p == nil {
		return Span{}, false
	}
	return restricted(p.SourcePort)
}

// DestinationPorts is SourcePorts for the destination port.
func (p *PortRange) DestinationPorts() (Span, bool) {
	if p == nil {
		return Span{}, false
	}
	return restricted(p.DestinationPort)
}

func restricted(r *Range) (Span, bool) {
	s, ok := r.span(AllPorts)
	if !ok || s == AllPorts {
		return Span{}, false
	}
	return s, true
}

// ACLParsed is a rule's parsed form; absent for remarks.
type ACLParsed struct {
	Action             string     `json:"action"`
	Name               string     `json:"name,omitempty"`
	Description        string     `json:"description,omitempty"`
	IPVersion          string     `json:"ipVersion,omitempty"`
	SourceAddress      string     `json:"sourceAddress,omitempty"`
	DestinationAddress string     `json:"destinationAddress,omitempty"`
	Protocol           *Range     `json:"protocol,omitempty"`
	TCP                *PortRange `json:"tcp,omitempty"`
	UDP                *PortRange `json:"udp,omitempty"`
	Established        bool       `json:"established,omitempty"`
	Fragments          bool       `json:"fragments,omitempty"`
}

// Protocols is the IP protocol numbers the rule matches, AllProtocols for
// every protocol; ok is false when the rule gives no protocol range.
func (p *ACLParsed) Protocols() (Span, bool) {
	if p == nil {
		return Span{}, false
	}
	return p.Protocol.span(AllProtocols)
}

// ACLRuleDetail is one rule of an ACL version fetched with details.
type ACLRuleDetail struct {
	Index     int        `json:"index"`
	ACLText   string     `json:"aclText,omitempty"`
	Comment   string     `json:"comment,omitempty"`
	IPVersion string     `json:"ipVersion,omitempty"`
	RuleUUID  string     `json:"ruleUuid,omitempty"`
	Parsed    *ACLParsed `json:"parsed,omitempty"`
}

// ACLVersionDetail is one ACL version with its rules.
type ACLVersionDetail struct {
	Version     int             `json:"version"`
	State       string          `json:"state"`
	Description string          `json:"description,omitempty"`
	CreatedBy   string          `json:"createdBy,omitempty"`
	Created     string          `json:"createdTimestamp,omitempty"`
	UpdatedBy   string          `json:"updatedBy,omitempty"`
	Updated     string          `json:"updatedTimestamp,omitempty"`
	Rules       []ACLRuleDetail `json:"ruleSet"`
}

// ACLVersion reads one ACL version with parsed rule details.
func (s *V2) ACLVersion(ctx context.Context, version int) (ACLVersionDetail, error) {
	var v ACLVersionDetail
	q := url.Values{"details": {"true"}}
	err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/acls/versions/" + strconv.Itoa(version), Query: q}, &v)
	if v.Rules == nil {
		v.Rules = []ACLRuleDetail{}
	}
	return v, err
}

// DeployStats counts a ruleset's rules by install state.
type DeployStats struct {
	Failed       int `json:"failed"`
	Installed    int `json:"installed"`
	NotInstalled int `json:"notInstalled"`
	Total        int `json:"total"`
}

// DeployedRule is one rule of a deployment-status ruleset.
type DeployedRule struct {
	ACLText       string `json:"aclText,omitempty"`
	InstallStatus string `json:"installStatus,omitempty" doc:"INSTALLED, NOT_INSTALLED or FAILED."`
	RuleUUID      string `json:"ruleUuid,omitempty"`
}

// DeploymentSet is one ruleset of the ACL deployment status.
type DeploymentSet struct {
	Status    string         `json:"deploymentStatus" doc:"PRODUCTION, PROCESSING or FAILED."`
	Version   int            `json:"version"`
	Hash      string         `json:"hash,omitempty"`
	Retrieved string         `json:"statusRetrievalTimestamp,omitempty"`
	Stats     DeployStats    `json:"rulesDeployStats"`
	Rules     []DeployedRule `json:"ruleSet"`
}

// DeploymentSets reads the deployment status's rulesets as the API sends them.
func (s *V2) DeploymentSets(ctx context.Context) ([]DeploymentSet, error) {
	var resp struct {
		RuleSets []DeploymentSet `json:"ruleSets"`
	}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/acls/versions/deployment-status"}, &resp); err != nil {
		return nil, err
	}
	for i := range resp.RuleSets {
		if resp.RuleSets[i].Rules == nil {
			resp.RuleSets[i].Rules = []DeployedRule{}
		}
	}
	if resp.RuleSets == nil {
		resp.RuleSets = []DeploymentSet{}
	}
	return resp.RuleSets, nil
}

// ProductionVersion is the version of the PRODUCTION ruleset; NotFound when
// none is in production.
func ProductionVersion(sets []DeploymentSet) (int, error) {
	for _, rs := range sets {
		if rs.Status == "PRODUCTION" && rs.Version != 0 {
			return rs.Version, nil
		}
	}
	return 0, apperr.New(apperr.NotFound, "no ACL version is in production")
}
