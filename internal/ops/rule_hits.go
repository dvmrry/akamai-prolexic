package ops

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

func writeHitRows(w io.Writer, rows []ncfapi.RuleHit) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tMATCHES\tBYTES\tFIRST MATCH\tLAST MATCH\tLAST RESET\tUPDATED")
	for _, h := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\n", h.RuleID, h.Matches, h.Bytes, dash(h.FirstMatch), dash(h.LastMatch), dash(h.LastReset), dash(h.LastUpdated))
	}
	return tw.Flush()
}

func writeSeries(w io.Writer, s *ncfapi.HitSeries) error {
	fmt.Fprintf(w, "\ntime series %s to %s, resolution %s: total %d, average %.1f, peak %.0f\n",
		s.Start, s.End, dash(s.Resolution), s.TotalMatches, s.AverageMatches, s.PeakMatches)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tMATCHES\tBYTES")
	for _, p := range s.Points {
		fmt.Fprintf(tw, "%s\t%d\t%d\n", p.Timestamp, p.Matches, p.Bytes)
	}
	return tw.Flush()
}

func sortHits(rows []ncfapi.RuleHit) {
	slices.SortStableFunc(rows, func(x, y ncfapi.RuleHit) int { return cmp.Compare(x.RuleID, y.RuleID) })
}

func sortPoints(s *ncfapi.HitSeries) {
	slices.SortStableFunc(s.Points, func(x, y ncfapi.HitPoint) int { return cmp.Compare(x.Timestamp, y.Timestamp) })
}

// RuleHitsDoc is the account-wide match statistics of every rule.
type RuleHitsDoc struct {
	output.Header
	RulesetName string           `json:"rulesetName,omitempty"`
	RulesetType string           `json:"rulesetType,omitempty"`
	Rules       []ncfapi.RuleHit `json:"rules" doc:"Sorted by ruleId."`
}

func (*RuleHitsDoc) SchemaID() string { return "prolexic.rule-hits.v1" }

func (d *RuleHitsDoc) WriteText(w io.Writer) error {
	if d.RulesetName != "" || d.RulesetType != "" {
		fmt.Fprintf(w, "ruleset %s (%s)\n", dash(d.RulesetName), dash(d.RulesetType))
	}
	return writeHitRows(w, d.Rules)
}

// RuleHits lists the match statistics of every rule.
func (r *Runtime) RuleHits(ctx context.Context) (*RuleHitsDoc, error) {
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	got, err := api.ListRuleHits(ctx)
	if err != nil {
		return nil, err
	}
	sortHits(got.Rules)
	return &RuleHitsDoc{RulesetName: got.RulesetName, RulesetType: got.RulesetType, Rules: nonNil(got.Rules)}, nil
}

// RuleHitDoc is one rule's match statistics, and its time series when a
// window was asked for.
type RuleHitDoc struct {
	output.Header
	Rule   ncfapi.RuleHit    `json:"rule"`
	Series *ncfapi.HitSeries `json:"series,omitempty" doc:"Present only when a window was given."`
}

func (*RuleHitDoc) SchemaID() string { return "prolexic.rule-hit.v1" }

func (d *RuleHitDoc) WriteText(w io.Writer) error {
	if err := writeHitRows(w, []ncfapi.RuleHit{d.Rule}); err != nil {
		return err
	}
	if d.Series == nil {
		return nil
	}
	return writeSeries(w, d.Series)
}

// RuleHitInput names one rule, and optionally a window for its time series.
type RuleHitInput struct {
	Rule   string // the rule id (the ruleId from RuleHits); required
	Window Window // zero means no time series
}

// RuleHit is one rule's match statistics, and its time series when a window
// was given.
func (r *Runtime) RuleHit(ctx context.Context, in RuleHitInput) (*RuleHitDoc, error) {
	if in.Rule == "" {
		return nil, apperr.New(apperr.Usage, "the rule id is required")
	}
	id := in.Rule
	start, end, given, err := in.Window.resolve(r.now(), 0)
	if err != nil {
		return nil, err
	}
	api, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	hit, err := api.GetRuleHit(ctx, id)
	if err != nil {
		return nil, err
	}
	doc := &RuleHitDoc{Rule: hit}
	if given {
		s, err := api.RuleTimeSeries(ctx, id, start, end)
		if err != nil {
			return nil, err
		}
		sortPoints(&s)
		doc.Series = &s
	}
	return doc, nil
}
