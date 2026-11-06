package ncfapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
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

// getPages reads every page of a Spring-style paged list (content, last,
// totalPages). It trusts "last", then "totalPages", and without either reads
// until an empty page, so a short answer is never mistaken for the whole.
func getPages[T any](ctx context.Context, c *akamai.Client, path string, query url.Values) ([]T, error) {
	var out []T
	for page := 0; ; page++ {
		var resp struct {
			Content    []T   `json:"content"`
			Last       *bool `json:"last"`
			TotalPages *int  `json:"totalPages"`
		}
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("page", strconv.Itoa(page))
		q.Set("size", "100")
		if err := c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: path, Query: q}, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Content...)
		switch {
		case resp.Last != nil:
			if *resp.Last {
				return out, nil
			}
		case resp.TotalPages != nil:
			if page+1 >= *resp.TotalPages {
				return out, nil
			}
		}
		if len(resp.Content) == 0 {
			return out, nil // nothing more, whatever "last" said: don't spin
		}
		if page >= 1000 {
			return nil, apperr.New(apperr.Upstream, "%s: the list did not end after %d pages", path, page+1)
		}
	}
}

// VersionInfo is one item of an alias's version history.
type VersionInfo struct {
	Version       string `json:"version"`
	Active        bool   `json:"active" doc:"The alias's active version."`
	EntriesCount  int    `json:"entriesCount"`
	Comment       string `json:"comment" doc:"The note the version was created with; empty when none."`
	SourceVersion string `json:"sourceVersion" doc:"The version it was derived from; empty when none."`
	UpdatedBy     string `json:"updatedBy,omitempty"`
	Updated       string `json:"updated,omitempty" doc:"When the version was last updated, as the API reports it."`
}

// VersionHistory reads an alias's full version history, every page.
func (s *V2) VersionHistory(ctx context.Context, id int64) ([]VersionInfo, error) {
	rows, err := getPages[struct {
		Version       string `json:"version"`
		IsActive      bool   `json:"isActive"`
		EntriesCount  int    `json:"entriesCount"`
		Comments      string `json:"comments"`
		SourceVersion string `json:"sourceVersion"`
		UpdatedBy     string `json:"updatedBy"`
		Updated       string `json:"updatedTimestamp"`
	}](ctx, s.c, s.aliasPath(id)+"/versions", nil)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, len(rows))
	for i, r := range rows {
		out[i] = VersionInfo{Version: r.Version, Active: r.IsActive, EntriesCount: r.EntriesCount, Comment: r.Comments,
			SourceVersion: r.SourceVersion, UpdatedBy: r.UpdatedBy, Updated: r.Updated}
	}
	return out, nil
}
