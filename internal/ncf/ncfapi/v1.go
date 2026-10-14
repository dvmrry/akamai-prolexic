// Package ncfapi maps ncf.Store onto the Network Cloud Firewall HTTP API.
//
// V1 serves reads from the public NCF v1 spec. NCF v1 has no alias
// versions, so the version-related methods are unsupported (exit 4) and
// apply refuses before writing anything. The NCF v2 adapter (versions,
// activation, BIG multipart upload) waits for the v2 spec, which is only
// published behind the Akamai login.
package ncfapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

const v1Path = "/network-cloud-firewall/v1"

// V1 is a read-only ncf.Store over NCF v1.
type V1 struct {
	c *akamai.Client
}

// NewV1 wraps a transport client.
func NewV1(c *akamai.Client) *V1 { return &V1{c: c} }

var _ ncf.Store = (*V1)(nil)

// alias is the v1 wire shape (acl-alias-by-id-response).
type alias struct {
	AccountID          string   `json:"accountId"`
	AliasID            int64    `json:"aliasId"`
	AliasListType      string   `json:"aliasListType"`
	AliasName          string   `json:"aliasName"`
	IPVersion          string   `json:"ipVersion"`
	IsCustomerEditable bool     `json:"isCustomerEditable"`
	EntriesCount       int      `json:"entriesCount"`
	Entries            []string `json:"entries"`
}

func (a alias) live(withEntries bool) ncf.LiveAlias {
	l := ncf.LiveAlias{
		ID: a.AliasID, Name: a.AliasName, Type: a.AliasListType, IPVersion: a.IPVersion,
		Editable: a.IsCustomerEditable, AccountID: a.AccountID, EntriesCount: a.EntriesCount,
	}
	if withEntries {
		l.Entries = a.Entries
		if l.Entries == nil {
			l.Entries = []string{}
		}
	}
	return l
}

// ListAliases lists every alias. v1 may include entries in the list, even
// for Akamai-managed aliases; they are dropped here, never returned.
func (s *V1) ListAliases(ctx context.Context) ([]ncf.LiveAlias, error) {
	var resp []alias
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v1Path + "/acls/aliases"}, &resp); err != nil {
		return nil, err
	}
	out := make([]ncf.LiveAlias, len(resp))
	for i, a := range resp {
		out[i] = a.live(false)
	}
	return out, nil
}

// GetAlias reads one alias with its entries.
func (s *V1) GetAlias(ctx context.Context, id int64) (ncf.LiveAlias, error) {
	var a alias
	err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v1Path + "/acls/aliases/" + strconv.FormatInt(id, 10)}, &a)
	return a.live(true), err
}

var errNeedsV2 = apperr.New(apperr.NotFound, "alias versions are unsupported by NCF v1; writes need the NCF v2 adapter")

func (s *V1) ListVersions(context.Context, int64) ([]ncf.AliasVersion, error) { return nil, errNeedsV2 }

func (s *V1) GetVersion(context.Context, int64, string) (ncf.AliasVersion, error) {
	return ncf.AliasVersion{}, errNeedsV2
}

func (s *V1) CreateVersion(context.Context, ncf.LiveAlias, []string) (string, error) {
	return "", errNeedsV2
}

func (s *V1) Activate(context.Context, int64, string) error { return errNeedsV2 }

// deploymentStatus is acl-deployment-status.
type deploymentStatus struct {
	RuleSets []struct {
		DeploymentStatus string `json:"deploymentStatus"`
		Version          int    `json:"version"`
		RulesDeployStats struct {
			Failed int `json:"failed"`
		} `json:"rulesDeployStats"`
	} `json:"ruleSets"`
}

// Deployment summarises the ACL deployment: the production version and its
// failed rules, and whether anything is processing.
func (s *V1) Deployment(ctx context.Context) (ncf.Deployment, error) {
	var resp deploymentStatus
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v1Path + "/acls/versions/deployment-status"}, &resp); err != nil {
		return ncf.Deployment{}, err
	}
	var d ncf.Deployment
	for _, rs := range resp.RuleSets {
		switch rs.DeploymentStatus {
		case "PRODUCTION":
			d.Version, d.State, d.FailedRules = rs.Version, rs.DeploymentStatus, rs.RulesDeployStats.Failed
		case "PROCESSING":
			d.Processing = true
		case "FAILED":
			d.FailedVersion = max(d.FailedVersion, rs.Version)
		}
	}
	if d.State == "" && d.FailedVersion != 0 {
		d.State = "FAILED"
	}
	return d, nil
}

// Limits reads the per-type alias limits from /stats.
func (s *V1) Limits(ctx context.Context) ([]ncf.Limit, error) {
	var resp struct {
		Aliases []struct {
			Type          string `json:"type"`
			Limit         int    `json:"limit"`
			EnabledCount  int    `json:"enabledCount"`
			DisabledCount int    `json:"disabledCount"`
		} `json:"aliases"`
	}
	if err := s.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: v1Path + "/stats"}, &resp); err != nil {
		return nil, err
	}
	out := make([]ncf.Limit, len(resp.Aliases))
	for i, a := range resp.Aliases {
		out[i] = ncf.Limit{Type: a.Type, Limit: a.Limit, Enabled: a.EnabledCount, Disabled: a.DisabledCount}
	}
	return out, nil
}
