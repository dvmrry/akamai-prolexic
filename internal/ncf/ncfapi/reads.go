package ncfapi

import (
	"context"
	"net/http"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

// Read-only calls beyond ncf.Store. The exported types carry JSON tags and
// docs because CLI documents embed them.

// AliasInfo is one item of GET /aliases, with the fields the Store's
// LiveAlias leaves out.
type AliasInfo struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type" doc:"SOURCE, DIPA or BIG."`
	IPVersion       string `json:"ipVersion"`
	Editable        bool   `json:"editable" doc:"False means Akamai-managed."`
	InUse           bool   `json:"inUse" doc:"A deployed ACL rule references the alias."`
	ActiveVersion   string `json:"activeVersion" doc:"Empty when none is reported."`
	ProdVersion     string `json:"prodVersion" doc:"The version production carries; empty when none."`
	ProdRuleIndexes []int  `json:"prodRuleIndexes" doc:"Indexes of the deployed ACL rules that reference the alias."`
	EntriesCount    int    `json:"entriesCount" doc:"Entries in the active version."`
}

// ListAliasInfo lists every alias (no entries).
func (s *V2) ListAliasInfo(ctx context.Context) ([]AliasInfo, error) {
	var resp []struct {
		AliasID       int64  `json:"aliasId"`
		AliasName     string `json:"aliasName"`
		AliasType     string `json:"aliasType"`
		IPVersion     string `json:"ipVersion"`
		Editable      bool   `json:"isCustomerEditable"`
		InUse         bool   `json:"inUse"`
		ActiveVersion *struct {
			Version      string `json:"version"`
			EntriesCount int    `json:"entriesCount"`
		} `json:"activeVersion"`
		ProdVersion *struct {
			Version string `json:"version"`
			// Live sends aclRuleIndexes; the spec says aclRules. Read both.
			Indexes []int `json:"aclRuleIndexes"`
			Rules   []int `json:"aclRules"`
		} `json:"prodVersion"`
	}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/aliases"}, &resp); err != nil {
		return nil, err
	}
	out := make([]AliasInfo, 0, len(resp))
	for _, a := range resp {
		i := AliasInfo{ID: a.AliasID, Name: a.AliasName, Type: a.AliasType, IPVersion: a.IPVersion,
			Editable: a.Editable, InUse: a.InUse, ProdRuleIndexes: []int{}}
		if a.ActiveVersion != nil {
			i.ActiveVersion, i.EntriesCount = a.ActiveVersion.Version, a.ActiveVersion.EntriesCount
		}
		if a.ProdVersion != nil {
			i.ProdVersion = a.ProdVersion.Version
			i.ProdRuleIndexes = append(i.ProdRuleIndexes, a.ProdVersion.Indexes...)
			if len(i.ProdRuleIndexes) == 0 {
				i.ProdRuleIndexes = append(i.ProdRuleIndexes, a.ProdVersion.Rules...)
			}
		}
		out = append(out, i)
	}
	return out, nil
}
