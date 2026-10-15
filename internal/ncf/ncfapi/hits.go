package ncfapi

import (
	"cmp"
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

// RuleHit is one rule's match statistics. Timestamps are as the API sends
// them.
type RuleHit struct {
	RuleID      string `json:"ruleId" doc:"The rule's id (its uuid)."`
	Matches     int64  `json:"matches"`
	Bytes       int64  `json:"bytes"`
	FirstMatch  string `json:"firstMatch,omitempty"`
	LastMatch   string `json:"lastMatch,omitempty"`
	LastReset   string `json:"lastReset,omitempty"`
	LastUpdated string `json:"lastUpdated,omitempty"`
}

// hitWire reads a RuleHit from either API: the account-wide one names the
// rule ruleId, the managed-services one ruleUuid.
type hitWire struct {
	RuleID      string `json:"ruleId"`
	RuleUUID    string `json:"ruleUuid"`
	Matches     int64  `json:"matches"`
	Bytes       int64  `json:"bytes"`
	FirstMatch  string `json:"firstMatch"`
	LastMatch   string `json:"lastMatch"`
	LastReset   string `json:"lastReset"`
	LastUpdated string `json:"lastUpdated"`
}

func (h hitWire) hit() RuleHit {
	return RuleHit{RuleID: cmp.Or(h.RuleID, h.RuleUUID), Matches: h.Matches, Bytes: h.Bytes,
		FirstMatch: h.FirstMatch, LastMatch: h.LastMatch, LastReset: h.LastReset, LastUpdated: h.LastUpdated}
}

func hits(w []hitWire) []RuleHit {
	out := make([]RuleHit, len(w))
	for i, h := range w {
		out[i] = h.hit()
	}
	return out
}

// RuleHits is the account-wide match statistics of a ruleset.
type RuleHits struct {
	RulesetName string    `json:"rulesetName,omitempty"`
	RulesetType string    `json:"rulesetType,omitempty"`
	Rules       []RuleHit `json:"rules"`
}

// ListRuleHits reads every rule's match statistics (the API does not page).
func (s *V2) ListRuleHits(ctx context.Context) (RuleHits, error) {
	var resp struct {
		RulesetName string    `json:"rulesetName"`
		RulesetType string    `json:"rulesetType"`
		Rules       []hitWire `json:"rules"`
	}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/rule-hits/rules"}, &resp); err != nil {
		return RuleHits{}, err
	}
	return RuleHits{RulesetName: resp.RulesetName, RulesetType: resp.RulesetType, Rules: hits(resp.Rules)}, nil
}

// GetRuleHit reads one rule's match statistics. The rule id is the id the
// list reports (a uuid), taken as an opaque string.
func (s *V2) GetRuleHit(ctx context.Context, rule string) (RuleHit, error) {
	var h hitWire
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/rule-hits/rules/" + rule}, &h); err != nil {
		return RuleHit{}, err
	}
	out := h.hit()
	out.RuleID = cmp.Or(out.RuleID, rule)
	return out, nil
}

// HitPoint is one bucket of a time series.
type HitPoint struct {
	Timestamp string `json:"timestamp"`
	Matches   int64  `json:"matches"`
	Bytes     int64  `json:"bytes"`
}

// HitSeries is a rule's match counts over a window.
type HitSeries struct {
	Start          string     `json:"start" doc:"Window start as the API reports it."`
	End            string     `json:"end" doc:"Window end as the API reports it."`
	Resolution     string     `json:"resolution,omitempty" doc:"Bucket size the API chose: 5m, 1h or 1d."`
	TotalMatches   int64      `json:"totalMatches"`
	AverageMatches float64    `json:"averageMatches"`
	PeakMatches    float64    `json:"peakMatches"`
	Points         []HitPoint `json:"points" doc:"In time order."`
}

type seriesWire struct {
	StartTime      string     `json:"startTime"`
	EndTime        string     `json:"endTime"`
	Resolution     string     `json:"resolution"`
	TotalMatches   int64      `json:"totalMatches"`
	AverageMatches float64    `json:"averageMatches"`
	PeakMatches    float64    `json:"peakMatches"`
	TimeSeries     []HitPoint `json:"timeSeries"`
}

func (w seriesWire) series(start, end time.Time) HitSeries {
	s := HitSeries{Start: cmp.Or(w.StartTime, start.UTC().Format(time.RFC3339)), End: cmp.Or(w.EndTime, end.UTC().Format(time.RFC3339)),
		Resolution: w.Resolution, TotalMatches: w.TotalMatches, AverageMatches: w.AverageMatches, PeakMatches: w.PeakMatches,
		Points: w.TimeSeries}
	if s.Points == nil {
		s.Points = []HitPoint{}
	}
	return s
}

func windowQuery(start, end time.Time) url.Values {
	return url.Values{"startTime": {start.UTC().Format(time.RFC3339)}, "endTime": {end.UTC().Format(time.RFC3339)}}
}

// RuleTimeSeries reads a rule's matches over [start, end).
func (s *V2) RuleTimeSeries(ctx context.Context, rule string, start, end time.Time) (HitSeries, error) {
	var w seriesWire
	req := akamai.Request{Method: http.MethodGet, Path: v2Path + "/rule-hits/rules/" + rule + "/time-series", Query: windowQuery(start, end)}
	if err := s.c.Do(ctx, req, &w); err != nil {
		return HitSeries{}, err
	}
	return w.series(start, end), nil
}
