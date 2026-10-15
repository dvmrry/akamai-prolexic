package ncfapi

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

const v2Path = "/network-cloud-firewall/v2"

// V2 is ncf.Store over NCF v2, where aliases are versioned.
//
// v2 has no "get one alias" (live returns 405): the alias list carries each
// alias's active and production version ids but no entries, and entries come
// from GET /aliases/{id}/versions/{version}. Live /versions/active carries
// no entries, so it isn't used.
type V2 struct {
	c *akamai.Client
}

// NewV2 wraps a transport client.
func NewV2(c *akamai.Client) *V2 { return &V2{c: c} }

var _ ncf.Store = (*V2)(nil)

// v2Alias is one item of GET /aliases.
type v2Alias struct {
	AccountID          string `json:"accountId"`
	AliasID            int64  `json:"aliasId"`
	AliasName          string `json:"aliasName"`
	AliasType          string `json:"aliasType"`
	IPVersion          string `json:"ipVersion"`
	IsCustomerEditable bool   `json:"isCustomerEditable"`
	ActiveVersion      *struct {
		Version      string `json:"version"`
		EntriesCount int    `json:"entriesCount"`
	} `json:"activeVersion"`
	ProdVersion *struct {
		Version string `json:"version"`
		// Live sends aclRuleIndexes; the spec says aclRules. Read both.
		ACLRuleIndexes []int `json:"aclRuleIndexes"`
		ACLRules       []int `json:"aclRules"`
	} `json:"prodVersion"`
}

func (a v2Alias) live() ncf.LiveAlias {
	l := ncf.LiveAlias{
		ID: a.AliasID, Name: a.AliasName, Type: a.AliasType, IPVersion: a.IPVersion,
		Editable: a.IsCustomerEditable, AccountID: a.AccountID,
	}
	if a.ActiveVersion != nil {
		l.ActiveVersion, l.EntriesCount = a.ActiveVersion.Version, a.ActiveVersion.EntriesCount
	}
	if a.ProdVersion != nil {
		l.ProdVersion = a.ProdVersion.Version
		l.ProdRules = a.ProdVersion.ACLRuleIndexes
		if len(l.ProdRules) == 0 {
			l.ProdRules = a.ProdVersion.ACLRules
		}
	}
	return l
}

// v2Version is the alias-version shape (get, active, create).
type v2Version struct {
	AliasID       int64    `json:"aliasId"`
	Version       string   `json:"version"`
	IsActive      bool     `json:"isActive"`
	Entries       []string `json:"entries"`
	Comments      string   `json:"comments"`
	SourceVersion string   `json:"sourceVersion"`
}

func (s *V2) ListAliases(ctx context.Context) ([]ncf.LiveAlias, error) {
	var resp []v2Alias
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/aliases"}, &resp); err != nil {
		return nil, err
	}
	out := make([]ncf.LiveAlias, len(resp))
	for i, a := range resp {
		out[i] = a.live()
	}
	return out, nil
}

// GetAlias returns one alias with its active version's entries. The token is
// the list's activeVersion, and the entries are read from that exact version
// (live /versions/active carries no entries), so the two always agree.
func (s *V2) GetAlias(ctx context.Context, id int64) (ncf.LiveAlias, error) {
	all, err := s.ListAliases(ctx)
	if err != nil {
		return ncf.LiveAlias{}, err
	}
	var l ncf.LiveAlias
	found := false
	for _, a := range all {
		if a.ID == id {
			l, found = a, true
		}
	}
	if !found {
		return ncf.LiveAlias{}, apperr.New(apperr.NotFound, "no alias %d", id)
	}
	if l.ActiveVersion == "" {
		return ncf.LiveAlias{}, apperr.New(apperr.Upstream, "alias %s (%d) lists no active version", l.Name, id)
	}
	v, err := s.GetVersion(ctx, id, l.ActiveVersion)
	if err != nil {
		return ncf.LiveAlias{}, err
	}
	l.Entries = v.Entries
	return l, nil
}

// ListVersions pages through the full version history (metadata only). A
// short history makes apply misjudge an ambiguous create, so getPages never
// stops early.
func (s *V2) ListVersions(ctx context.Context, id int64) ([]ncf.AliasVersion, error) {
	rows, err := getPages[v2Version](ctx, s.c, s.aliasPath(id)+"/versions", nil)
	if err != nil {
		return nil, err
	}
	out := make([]ncf.AliasVersion, len(rows))
	for i, v := range rows {
		out[i] = ncf.AliasVersion{Version: v.Version, Active: v.IsActive, Comment: v.Comments, Source: v.SourceVersion}
	}
	return out, nil
}

func (s *V2) GetVersion(ctx context.Context, id int64, version string) (ncf.AliasVersion, error) {
	var v v2Version
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: s.versionPath(id, version)}, &v); err != nil {
		return ncf.AliasVersion{}, err
	}
	if v.Entries == nil {
		v.Entries = []string{}
	}
	return ncf.AliasVersion{Version: v.Version, Active: v.IsActive, Entries: v.Entries}, nil
}

// CreateVersion creates an inactive version for SOURCE and DIPA aliases
// (isActive must be sent false: the API defaults it to true). BIG aliases
// take a multipart .txt upload, which has no inactive option; the response
// says whether it went live.
func (s *V2) CreateVersion(ctx context.Context, alias ncf.LiveAlias, entries []string, comment string) (ncf.AliasVersion, error) {
	var v v2Version
	var req akamai.Request
	if entries == nil {
		entries = []string{} // "entries": null is not "empty the alias"
	}
	if alias.Type == "BIG" {
		body, contentType, err := bigUpload(alias, entries)
		if err != nil {
			return ncf.AliasVersion{}, err
		}
		req = akamai.Request{Method: http.MethodPost, Path: v2Path + "/big-aliases/" + strconv.FormatInt(alias.ID, 10) + "/versions", Body: body, ContentType: contentType}
	} else {
		if alias.ActiveVersion == "" {
			return ncf.AliasVersion{}, apperr.New(apperr.Bug, "create a version of %s: no source version (the planned active version is unknown)", alias.Name)
		}
		req = akamai.Request{Method: http.MethodPost, Path: s.aliasPath(alias.ID) + "/versions", JSON: struct {
			Entries       []string `json:"entries"`
			SourceVersion string   `json:"sourceVersion"`
			IsActive      bool     `json:"isActive"`
			Comments      string   `json:"comments,omitempty"`
		}{entries, alias.ActiveVersion, false, truncate(comment, 255)}}
	}
	if err := s.c.Do(ctx, req, &v); err != nil {
		return ncf.AliasVersion{}, err
	}
	if v.Version == "" {
		// Created, but we can't tell which version: as ambiguous as a lost
		// response, so the caller proves it from the version list.
		return ncf.AliasVersion{}, &apperr.Error{Code: apperr.Upstream, Message: "create version: the response names no version",
			Upstream: &apperr.UpstreamDetail{Method: req.Method, Path: req.Path, Ambiguous: true}}
	}
	return ncf.AliasVersion{Version: v.Version, Active: v.IsActive}, nil
}

// bigUpload is the multipart form of POST /big-aliases/{id}/versions: the
// entries as a .txt file, one per line, plus aliasName and ipVersion.
func bigUpload(alias ncf.LiveAlias, entries []string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("aliasName", alias.Name); err != nil {
		return nil, "", err
	}
	if err := w.WriteField("ipVersion", alias.IPVersion); err != nil {
		return nil, "", err
	}
	fw, err := w.CreateFormFile("file", alias.Name+".txt")
	if err != nil {
		return nil, "", err
	}
	if _, err := fmt.Fprint(fw, strings.Join(entries, "\n")+"\n"); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

func (s *V2) Activate(ctx context.Context, id int64, version string) error {
	return s.c.Do(ctx, akamai.Request{Method: http.MethodPatch, Path: s.versionPath(id, version) + "/activate"}, nil)
}

// Deployment and Limits have the same shapes as v1 at the v2 path.
func (s *V2) Deployment(ctx context.Context) (ncf.Deployment, error) {
	return deployment(ctx, s.c, v2Path)
}

func (s *V2) Limits(ctx context.Context) ([]ncf.Limit, error) {
	return limits(ctx, s.c, v2Path)
}

// DeployedRules reads the production ACL version (from deployment status)
// with details, and returns each rule's index, action and parsed addresses.
// Rules without parsed details (remarks) are skipped.
func (s *V2) DeployedRules(ctx context.Context) ([]ncf.ACLRule, error) {
	d, err := s.Deployment(ctx)
	if err != nil {
		return nil, err
	}
	if d.State != "PRODUCTION" || d.Version == 0 {
		return nil, nil
	}
	var resp struct {
		RuleSet []struct {
			Index  int `json:"index"`
			Parsed *struct {
				Action             string `json:"action"`
				SourceAddress      string `json:"sourceAddress"`
				DestinationAddress string `json:"destinationAddress"`
			} `json:"parsed"`
		} `json:"ruleSet"`
	}
	q := url.Values{"details": {"true"}}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v2Path + "/acls/versions/" + strconv.Itoa(d.Version), Query: q}, &resp); err != nil {
		return nil, err
	}
	var out []ncf.ACLRule
	for _, r := range resp.RuleSet {
		if r.Parsed == nil {
			continue
		}
		out = append(out, ncf.ACLRule{Index: r.Index, Action: r.Parsed.Action, Source: r.Parsed.SourceAddress, Destination: r.Parsed.DestinationAddress})
	}
	return out, nil
}

func (s *V2) aliasPath(id int64) string {
	return v2Path + "/aliases/" + strconv.FormatInt(id, 10)
}

func (s *V2) versionPath(id int64, version string) string {
	// The transport escapes paths itself; version ids are like "V1".
	return s.aliasPath(id) + "/versions/" + version
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
