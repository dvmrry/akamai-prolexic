package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// pathSafe rejects a value that can't be one path segment.
func pathSafe(flag, v string) (string, error) {
	if v == "" {
		return "", apperr.New(apperr.Usage, "--%s is required", flag)
	}
	if strings.Contains(v, "/") || v == "." || v == ".." {
		return "", apperr.New(apperr.Usage, "--%s %q can't be a path segment", flag, v)
	}
	return v, nil
}

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

func newRuleHitsListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "match statistics of every rule",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return ruleHitsList(ctx, a)
		}),
	}
}

func ruleHitsList(ctx context.Context, a *app) (output.Document, error) {
	api, err := a.ncfV2()
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
	Series *ncfapi.HitSeries `json:"series,omitempty" doc:"Present only when --since or --start was given."`
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

func newRuleHitsShowCmd(a *app) *cobra.Command {
	var rule string
	var win windowFlags
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one rule's statistics, and its time series with a window",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return ruleHitsShow(ctx, a, rule, win)
		}),
	}
	cmd.Flags().StringVar(&rule, "rule", "", "rule id (the ruleId from rule-hits list; required)")
	win.register(cmd, 0)
	_ = cmd.MarkFlagRequired("rule")
	return cmd
}

func ruleHitsShow(ctx context.Context, a *app, rule string, win windowFlags) (output.Document, error) {
	id, err := pathSafe("rule", rule)
	if err != nil {
		return nil, err
	}
	start, end, given, err := win.resolve(a.env.Now())
	if err != nil {
		return nil, err
	}
	api, err := a.ncfV2()
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
