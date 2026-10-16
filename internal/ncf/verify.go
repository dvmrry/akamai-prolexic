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
	SameSet       bool     `json:"sameSet" doc:"The live entries hash to the plan's desiredHash: exactly the expected set."`
	Problems      []string `json:"problems" doc:"What doesn't match, in words."`
}

// VerifyResult compares a plan's expected end state with a fresh read.
type VerifyResult struct {
	AccountID  string        `json:"accountId"`
	Digest     string        `json:"digest" doc:"The verified plan's digest."`
	Verified   bool          `json:"verified" doc:"Every alias matched and the ACL deployment is healthy and settled."`
	Aliases    []AliasVerify `json:"aliases"`
	Deployment []string      `json:"deployment" doc:"What is wrong with the ACL deployment: failed, or still processing. Empty when healthy."`
}

// Verify reads every alias in p fresh and checks the plan's expected end
// state: each added entry live, each removed entry gone, exactly the expected
// set (desiredHash), production carrying the active version (and still
// carrying the alias if the plan saw it in production), and a healthy,
// settled ACL deployment. It is the post-apply check a pipeline runs against
// the plan it reviewed. A plan whose digest doesn't match its aliases (edited
// or truncated) is refused, as is one with errors (it was never applied).
func Verify(ctx context.Context, store Store, p *Plan) (*VerifyResult, error) {
	if HasErrors(p.Findings) {
		return nil, apperr.New(apperr.Validation, "the plan has errors, so it was never applied; nothing to verify")
	}
	if got := digest(p.Aliases); got != p.Digest {
		return nil, apperr.New(apperr.Validation, "the plan's digest %s doesn't match its aliases (%s): the file was edited or truncated", p.Digest, got)
	}
	res := &VerifyResult{AccountID: p.AccountID, Digest: p.Digest, Verified: true, Aliases: []AliasVerify{}, Deployment: []string{}}
	// One alias list, then each alias's entries by version: not a full list
	// per alias.
	all, err := store.ListAliases(ctx)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindOf(err), err, "list aliases")
	}
	byID := make(map[int64]LiveAlias, len(all))
	for _, l := range all {
		byID[l.ID] = l
	}
	for _, ap := range p.Aliases {
		if ap.DesiredHash == "" {
			return nil, apperr.New(apperr.Validation, "alias %s has no desiredHash: not a plan this version of prolexic made", ap.Name)
		}
		row, ok := byID[ap.ID]
		if !ok {
			return nil, apperr.New(apperr.NotFound, "alias %s (%d) is no longer listed", ap.Name, ap.ID)
		}
		live, err := withEntries(ctx, store, row)
		if err != nil {
			return nil, apperr.Wrap(apperr.KindOf(err), err, "read %s", ap.Name)
		}
		v := verifyAlias(ap, live)
		res.Verified = res.Verified && v.Verified
		res.Aliases = append(res.Aliases, v)
	}
	d, err := store.Deployment(ctx)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindOf(err), err, "read ACL deployment status")
	}
	if why := d.Failure(); why != "" {
		res.Deployment = append(res.Deployment, "the ACL deployment is unhealthy: "+why)
	}
	if d.Processing {
		res.Deployment = append(res.Deployment, "the ACL deployment is still processing")
	}
	if d.Version == 0 && slices.ContainsFunc(res.Aliases, func(a AliasVerify) bool { return a.ProdVersion != "" }) {
		res.Deployment = append(res.Deployment, "the ACL deployment status shows no production ACL version, though an alias is in production")
	}
	res.Verified = res.Verified && len(res.Deployment) == 0
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
	v.SameSet = entriesHash(live.Entries) == ap.DesiredHash
	if live.Name != ap.Name {
		v.Problems = append(v.Problems, fmt.Sprintf("alias %d is now named %s", ap.ID, live.Name))
	}
	if len(v.Missing) > 0 {
		v.Problems = append(v.Problems, count(len(v.Missing), "added entry isn't live", "added entries aren't live"))
	}
	if len(v.StillLive) > 0 {
		v.Problems = append(v.Problems, count(len(v.StillLive), "removed entry is still live", "removed entries are still live"))
	}
	if v.Live != v.Want {
		v.Problems = append(v.Problems, fmt.Sprintf("%d entries live, want %d", v.Live, v.Want))
	}
	if !v.SameSet && len(v.Missing) == 0 && len(v.StillLive) == 0 && v.Live == v.Want {
		v.Problems = append(v.Problems, "the live entries aren't the expected set: an entry the plan left unchanged was replaced")
	}
	switch {
	case live.ProdVersion == "" && ap.ProdVersion != "":
		v.ProductionLag = true
		v.Problems = append(v.Problems, fmt.Sprintf("no longer in production (the plan saw production at %s): no deployed rule uses it now", ap.ProdVersion))
	case live.ProdVersion != "" && live.ProdVersion != live.ActiveVersion:
		v.ProductionLag = true
		v.Problems = append(v.Problems, fmt.Sprintf("production carries %s, not the active %s", live.ProdVersion, live.ActiveVersion))
	}
	// Live still at the version the plan started from, with changes planned:
	// most likely apply hasn't run yet. Say so, for whoever reads this cold.
	if len(v.Problems) > 0 && live.ActiveVersion == ap.ActiveVersion && len(ap.Add)+len(ap.Remove) > 0 {
		v.Problems = append(v.Problems, fmt.Sprintf("still at %s, the version the plan started from: the plan looks unapplied", ap.ActiveVersion))
	}
	slices.Sort(v.Missing)
	slices.Sort(v.StillLive)
	v.Verified = len(v.Problems) == 0
	return v
}

// count is "n one" or "n many", for n.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
