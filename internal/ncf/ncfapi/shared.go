// Package ncfapi maps ncf.Store onto the Network Cloud Firewall HTTP API.
//
// V2 is the adapter (versioned aliases, activation, BIG multipart upload).
// This file holds what the adapter reads from the unversioned parts of the
// API: ACL deployment status and the per-type alias limits.
package ncfapi

import (
	"context"
	"net/http"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

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

// deployment summarises the ACL deployment from deployment-status: the
// production version and its failed rules, and whether anything is
// processing.
func deployment(ctx context.Context, c *akamai.Client, base string) (ncf.Deployment, error) {
	var resp deploymentStatus
	if err := c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: base + "/acls/versions/deployment-status"}, &resp); err != nil {
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

// limits reads the per-type alias limits from /stats.
func limits(ctx context.Context, c *akamai.Client, base string) ([]ncf.Limit, error) {
	var resp struct {
		Aliases []struct {
			Type          string `json:"type"`
			Limit         int    `json:"limit"`
			EnabledCount  int    `json:"enabledCount"`
			DisabledCount int    `json:"disabledCount"`
		} `json:"aliases"`
	}
	if err := c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: base + "/stats"}, &resp); err != nil {
		return nil, err
	}
	out := make([]ncf.Limit, len(resp.Aliases))
	for i, a := range resp.Aliases {
		out[i] = ncf.Limit{Type: a.Type, Limit: a.Limit, Enabled: a.EnabledCount, Disabled: a.DisabledCount}
	}
	return out, nil
}
