package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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

func newManagedACLCmd(a *app) *cobra.Command {
	var domain string
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "a policy domain's latest managed-services ACL version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return managedACL(ctx, a, domain)
		}),
	}
	cmd.Flags().StringVar(&domain, "policy-domain", "", "policy domain (required)")
	_ = cmd.MarkFlagRequired("policy-domain")
	return cmd
}

func managedACL(ctx context.Context, a *app, domain string) (output.Document, error) {
	d, err := requireFlag("policy-domain", domain)
	if err != nil {
		return nil, err
	}
	api, err := a.ncfV2()
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
// rule's time series when --rule was given.
type ManagedRuleHitsDoc struct {
	output.Header
	PolicyDomain string            `json:"policyDomain"`
	Rules        []ncfapi.RuleHit  `json:"rules" doc:"Sorted by ruleId. With --rule, only that rule."`
	Series       *ncfapi.HitSeries `json:"series,omitempty" doc:"Present only with --rule: that rule's time series over the window (default the last 24h)."`
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

func newManagedRuleHitsCmd(a *app) *cobra.Command {
	var domain, rule string
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "rule-hits",
		Short: "a policy domain's rule statistics, and one rule's time series",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return managedRuleHits(ctx, a, domain, rule, win)
		}),
	}
	f := cmd.Flags()
	f.StringVar(&domain, "policy-domain", "", "policy domain (required)")
	f.StringVar(&rule, "rule", "", "one rule's id (its uuid): show that rule and its time series")
	win.register(cmd, 0)
	_ = cmd.MarkFlagRequired("policy-domain")
	return cmd
}

func managedRuleHits(ctx context.Context, a *app, domain, rule string, win windowFlags) (output.Document, error) {
	d, err := requireFlag("policy-domain", domain)
	if err != nil {
		return nil, err
	}
	var id string
	if rule != "" {
		if id, err = requireFlag("rule", rule); err != nil {
			return nil, err
		}
	}
	start, end, given, err := win.resolve(a.env.Now())
	if err != nil {
		return nil, err
	}
	if given && id == "" {
		return nil, apperr.New(apperr.Usage, "a time window needs --rule: only a rule has a time series")
	}
	if id != "" && !given {
		end = a.env.Now().UTC()
		start = end.Add(-24 * time.Hour)
	}
	api, err := a.ncfV2()
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
