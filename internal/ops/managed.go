package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ManagedACLDoc is a policy domain's latest managed-services ACL version.
type ManagedACLDoc struct {
	output.Header
	PolicyDomain string               `json:"policyDomain"`
	Version      int                  `json:"version"`
	State        string               `json:"state"`
	UpdatedBy    string               `json:"updatedBy,omitempty"`
	Updated      string               `json:"updated,omitempty"`
	Rules        []ncfapi.ManagedRule `json:"rules" doc:"In index order."`
}

func (*ManagedACLDoc) SchemaID() string { return "prolexic.managed-acl.v1" }

func (d *ManagedACLDoc) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "policy domain %s: managed ACL version %d, state %s, %d rules\n", d.PolicyDomain, d.Version, dash(d.State), len(d.Rules))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INDEX\tIP\tDESTINATION\tLOCATIONS\tRULE")
	for _, r := range d.Rules {
		dest := r.Destination
		if r.AnyDestination {
			dest = "any"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.Index, dash(r.IPVersion), dash(dest), dash(strings.Join(r.Locations, ",")), dash(r.ACLText))
	}
	return tw.Flush()
}

// ManagedACLInput names a policy domain.
type ManagedACLInput struct {
	PolicyDomain string // required
}

// ManagedACL is a policy domain's latest managed-services ACL version.
func (r *Runtime) ManagedACL(ctx context.Context, in ManagedACLInput) (*ManagedACLDoc, error) {
	if in.PolicyDomain == "" {
		return nil, apperr.New(apperr.Usage, "the policy domain is required")
	}
	d := in.PolicyDomain
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	got, err := api.GetManagedACL(ctx, d)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(got.Rules, func(x, y ncfapi.ManagedRule) int { return cmp.Compare(x.Index, y.Index) })
	return &ManagedACLDoc{PolicyDomain: cmp.Or(got.PolicyDomain, d), Version: got.Version, State: got.State,
		UpdatedBy: got.UpdatedBy, Updated: got.Updated, Rules: got.Rules}, nil
}

// ManagedRuleHitsDoc is a policy domain's rule match statistics, and one
// rule's time series when a rule was given.
type ManagedRuleHitsDoc struct {
	output.Header
	PolicyDomain string            `json:"policyDomain"`
	Rules        []ncfapi.RuleHit  `json:"rules" doc:"Sorted by ruleId. With a rule given, only that rule."`
	Series       *ncfapi.HitSeries `json:"series,omitempty" doc:"Present only when a rule was given: that rule's time series over the window (default the last 24h)."`
}

func (*ManagedRuleHitsDoc) SchemaID() string { return "prolexic.managed-rule-hits.v1" }

func (d *ManagedRuleHitsDoc) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "policy domain %s\n", d.PolicyDomain)
	if err := writeHitRows(w, d.Rules); err != nil {
		return err
	}
	if d.Series == nil {
		return nil
	}
	return writeSeries(w, d.Series)
}

// ManagedRuleHitsDefaultSince is the series window ManagedRuleHits reads for a
// rule when none is given.
const ManagedRuleHitsDefaultSince = 24 * time.Hour

// ManagedRuleHitsInput names a policy domain, and optionally one rule.
type ManagedRuleHitsInput struct {
	PolicyDomain string // required
	Rule         string // one rule's id (its uuid); empty means every rule, with no time series
	Window       Window // the rule's series window; needs Rule; zero means the last ManagedRuleHitsDefaultSince
}

// ManagedRuleHits is a policy domain's rule match statistics, and one rule's
// time series when a rule was given.
func (r *Runtime) ManagedRuleHits(ctx context.Context, in ManagedRuleHitsInput) (*ManagedRuleHitsDoc, error) {
	if in.PolicyDomain == "" {
		return nil, apperr.New(apperr.Usage, "the policy domain is required")
	}
	d, id := in.PolicyDomain, in.Rule
	var def time.Duration
	if id != "" {
		def = ManagedRuleHitsDefaultSince
	}
	start, end, given, err := in.Window.resolve(r.now(), def)
	if err != nil {
		return nil, err
	}
	if given && id == "" {
		return nil, apperr.New(apperr.Usage, "a time window needs a rule: only a rule has a time series")
	}
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	got, err := api.ListManagedRuleHits(ctx, d)
	if err != nil {
		return nil, err
	}
	doc := &ManagedRuleHitsDoc{PolicyDomain: cmp.Or(got.PolicyDomain, d), Rules: nonNil(got.Rules)}
	if id != "" {
		doc.Rules = slices.DeleteFunc(doc.Rules, func(h ncfapi.RuleHit) bool { return h.RuleID != id })
		if len(doc.Rules) == 0 {
			return nil, apperr.New(apperr.NotFound, "policy domain %s has no rule %s", d, id)
		}
		s, err := api.ManagedRuleTimeSeries(ctx, d, id, start, end)
		if err != nil {
			return nil, err
		}
		sortPoints(&s)
		doc.Series = &s
	}
	sortHits(doc.Rules)
	return doc, nil
}
