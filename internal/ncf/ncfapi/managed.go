package ncfapi

import (
	"context"
	"net/http"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

func managedPath(domain string) (string, error) {
	d, err := akamai.PathSegment("policy domain", domain)
	if err != nil {
		return "", err
	}
	return v2Path + "/policy-domains/" + d + "/managed-services-acls", nil
}

// ManagedRule is one rule of a managed-services ACL version.
type ManagedRule struct {
	Index          int      `json:"index"`
	ACLText        string   `json:"aclText,omitempty"`
	Destination    string   `json:"destination,omitempty"`
	AnyDestination bool     `json:"anyDestination,omitempty"`
	IPVersion      string   `json:"ipVersion,omitempty"`
	Locations      []string `json:"locations"`
	RuleUUID       string   `json:"ruleUuid,omitempty"`
}

// ManagedACL is the latest managed-services ACL version of a policy domain.
type ManagedACL struct {
	PolicyDomain string        `json:"policyDomain,omitempty"`
	Version      int           `json:"version"`
	State        string        `json:"state" doc:"CONFIGURATION, DEPLOYED or DEPRECATED."`
	CreatedBy    string        `json:"createdBy,omitempty"`
	Created      string        `json:"created,omitempty" doc:"As the API reports it."`
	UpdatedBy    string        `json:"updatedBy,omitempty"`
	Updated      string        `json:"updated,omitempty" doc:"As the API reports it."`
	Rules        []ManagedRule `json:"rules"`
}

// GetManagedACL reads the latest managed-services ACL version.
func (s *V2) GetManagedACL(ctx context.Context, domain string) (ManagedACL, error) {
	base, err := managedPath(domain)
	if err != nil {
		return ManagedACL{}, err
	}
	var resp struct {
		PolicyDomain string        `json:"policyDomain"`
		Version      int           `json:"version"`
		State        string        `json:"state"`
		CreatedBy    string        `json:"createdBy"`
		Created      string        `json:"createdTimestamp"`
		UpdatedBy    string        `json:"updatedBy"`
		Updated      string        `json:"updatedTimestamp"`
		RuleSet      []ManagedRule `json:"ruleSet"`
	}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: base + "/version"}, &resp); err != nil {
		return ManagedACL{}, err
	}
	out := ManagedACL{PolicyDomain: resp.PolicyDomain, Version: resp.Version, State: resp.State, CreatedBy: resp.CreatedBy,
		Created: resp.Created, UpdatedBy: resp.UpdatedBy, Updated: resp.Updated, Rules: resp.RuleSet}
	if out.Rules == nil {
		out.Rules = []ManagedRule{}
	}
	for i := range out.Rules {
		if out.Rules[i].Locations == nil {
			out.Rules[i].Locations = []string{}
		}
	}
	return out, nil
}

// ManagedRuleHits is a policy domain's match statistics per rule.
type ManagedRuleHits struct {
	PolicyDomain string    `json:"policyDomain,omitempty"`
	Rules        []RuleHit `json:"rules"`
}

// ListManagedRuleHits reads every managed-services rule's match statistics.
func (s *V2) ListManagedRuleHits(ctx context.Context, domain string) (ManagedRuleHits, error) {
	base, err := managedPath(domain)
	if err != nil {
		return ManagedRuleHits{}, err
	}
	var resp struct {
		PolicyDomain string    `json:"policyDomain"`
		Rules        []hitWire `json:"rules"`
	}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: base + "/rule-hits"}, &resp); err != nil {
		return ManagedRuleHits{}, err
	}
	return ManagedRuleHits{PolicyDomain: resp.PolicyDomain, Rules: hits(resp.Rules)}, nil
}

// ManagedRuleTimeSeries reads a managed-services rule's matches over a window.
func (s *V2) ManagedRuleTimeSeries(ctx context.Context, domain, rule string, start, end time.Time) (HitSeries, error) {
	base, err := managedPath(domain)
	if err != nil {
		return HitSeries{}, err
	}
	r, err := akamai.PathSegment("rule id", rule)
	if err != nil {
		return HitSeries{}, err
	}
	return s.ruleSeries(ctx, base+"/rule-hits/rules/"+r+"/time-series", start, end)
}
