package ncf

import (
	"context"
	"fmt"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// AliasVerify is how one alias compares with the plan's expected end state.
type AliasVerify struct {
	Name          string   `json:"name"`
	ID            int64    `json:"id"`
	Verified      bool     `json:"verified" doc:"Every added entry is live, no removed entry is, the count matches, and production carries the active version."`
	ActiveVersion string   `json:"activeVersion"`
	ProdVersion   string   `json:"prodVersion" doc:"Empty when no deployed rule uses the alias: nothing to carry."`
	Missing       []string `json:"missing" doc:"Entries the plan adds that aren't live."`
	StillLive     []string `json:"stillLive" doc:"Entries the plan removes that are still live."`
	Live          int      `json:"live" doc:"Live entry count."`
	Want          int      `json:"want" doc:"Expected count: the plan's unchanged entries plus its additions."`
	ProductionLag bool     `json:"productionLag" doc:"Production doesn't carry the active version yet."`
	Problems      []string `json:"problems" doc:"What doesn't match, in words."`
}

// VerifyResult compares a plan's expected end state with a fresh read.
type VerifyResult struct {
	Digest   string        `json:"digest" doc:"The verified plan's digest."`
	Verified bool          `json:"verified" doc:"Every alias matched."`
	Aliases  []AliasVerify `json:"aliases"`
}

// Verify reads every alias in p fresh and checks it against the plan's
// expected end state: each added entry live, each removed entry gone, the
// count equal to unchanged plus added (so nothing extra), and production
// carrying the active version. It is the post-apply check a pipeline runs
// against the plan it reviewed. A plan with errors was never applied, so
// it is refused.
func Verify(ctx context.Context, store Store, p *Plan) (*VerifyResult, error) {
	if HasErrors(p.Findings) {
		return nil, apperr.New(apperr.Validation, "the plan has errors, so it was never applied; nothing to verify")
	}
	res := &VerifyResult{Digest: p.Digest, Verified: true, Aliases: []AliasVerify{}}
	for _, ap := range p.Aliases {
		live, err := store.GetAlias(ctx, ap.ID)
		if err != nil {
			return nil, apperr.Wrap(apperr.KindOf(err), err, "read %s", ap.Name)
		}
		v := verifyAlias(ap, live)
		res.Verified = res.Verified && v.Verified
		res.Aliases = append(res.Aliases, v)
	}
	return res, nil
}

func verifyAlias(ap AliasPlan, live LiveAlias) AliasVerify {
	v := AliasVerify{Name: ap.Name, ID: ap.ID, ActiveVersion: live.ActiveVersion, ProdVersion: live.ProdVersion,
		Missing: []string{}, StillLive: []string{}, Live: len(live.Entries), Want: ap.Unchanged + len(ap.Add), Problems: []string{}}
	key := func(s string) string {
		if e, err := ParseLive(s); err == nil {
			return e.String()
		}
		return s
	}
	have := map[string]bool{}
	for _, e := range live.Entries {
		have[key(e)] = true
	}
	for _, e := range ap.Add {
		if !have[key(e.CIDR)] {
			v.Missing = append(v.Missing, e.CIDR)
		}
	}
	for _, e := range ap.Remove {
		if have[key(e.CIDR)] {
			v.StillLive = append(v.StillLive, e.CIDR)
		}
	}
	if live.Name != ap.Name {
		v.Problems = append(v.Problems, fmt.Sprintf("alias %d is now named %s", ap.ID, live.Name))
	}
	if len(v.Missing) > 0 {
		v.Problems = append(v.Problems, fmt.Sprintf("%d added entries aren't live", len(v.Missing)))
	}
	if len(v.StillLive) > 0 {
		v.Problems = append(v.Problems, fmt.Sprintf("%d removed entries are still live", len(v.StillLive)))
	}
	if v.Live != v.Want {
		v.Problems = append(v.Problems, fmt.Sprintf("%d entries live, want %d", v.Live, v.Want))
	}
	if live.ProdVersion != "" && live.ProdVersion != live.ActiveVersion {
		v.ProductionLag = true
		v.Problems = append(v.Problems, fmt.Sprintf("production carries %s, not the active %s", live.ProdVersion, live.ActiveVersion))
	}
	slices.Sort(v.Missing)
	slices.Sort(v.StillLive)
	v.Verified = len(v.Problems) == 0
	return v
}
