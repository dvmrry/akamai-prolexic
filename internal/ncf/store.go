package ncf

import (
	"context"
	"fmt"
	"net/netip"
)

// LiveAlias is an alias as the API reports it.
type LiveAlias struct {
	ID        int64
	Name      string
	Type      string // SOURCE, BIG or DIPA
	IPVersion string // V4 or V6
	Editable  bool   // isCustomerEditable; false means Akamai-managed
	AccountID string

	// ActiveVersion is the plan-time conflict token. ProdVersion is the
	// version production carries. Version ids are opaque strings (live
	// NCF v2 uses ids like "V1"); both are empty when the API doesn't
	// expose versions. There is no per-alias version limit.
	ActiveVersion string
	ProdVersion   string
	// ProdRules are the indexes of the deployed ACL rules that reference the
	// alias (prodVersion.aclRuleIndexes); empty when no deployed rule does.
	ProdRules []int

	EntriesCount int
	// Entries is nil unless fetched with GetAlias. Never fetch them for an
	// Akamai-managed alias.
	Entries []string
}

// AliasVersion is one version of an alias.
type AliasVersion struct {
	Version string
	Active  bool // the alias's active version
	// Entries is nil unless fetched with GetVersion.
	Entries []string
}

// Deployment is the account's ACL deployment state.
type Deployment struct {
	Version       int    // the ACL version in production; 0 if none
	State         string // the production ruleset's state, or FAILED when nothing is in production
	FailedRules   int    // production rules that failed to install; non-zero is a partial failure
	Processing    bool   // a version is being staged
	FailedVersion int    // the newest FAILED ruleset; 0 if none
}

// Failure says why the deployment is not healthy, or "" when it is. A
// FAILED ruleset at or after the production version is a failure even when
// it reports no failed rules; an older one is history.
func (d Deployment) Failure() string {
	switch {
	case d.FailedRules > 0:
		return fmt.Sprintf("production ACL version %d reports %d failed rules", d.Version, d.FailedRules)
	case d.FailedVersion != 0 && d.FailedVersion >= d.Version:
		return fmt.Sprintf("ACL version %d FAILED to deploy (production is %d)", d.FailedVersion, d.Version)
	}
	return ""
}

// ACLRule is one rule of the deployed ACL version, as far as deriving an
// alias's side needs it. Source and Destination are the parsed addresses,
// which name an alias bare ("block-v4") or qualified ("SRC::<account>::block-v4").
type ACLRule struct {
	Index       int
	Action      string
	Source      string
	Destination string
}

// Limit is the account's alias limit for one type.
type Limit struct {
	Type     string
	Limit    int
	Enabled  int
	Disabled int
}

// Store is the NCF API as plan and apply need it. The HTTP adapter maps it
// onto the wire; tests use ncftest.Store.
//
// Contract:
//   - ListAliases never returns entries (EntriesCount only).
//   - CreateVersion creates a version holding exactly entries, derived from
//     alias.ActiveVersion, with comment as its audit note. It asks for an
//     inactive version; a BIG alias takes a multipart upload, which may
//     activate on arrival, and the returned Active says so. It is never
//     retried: on an ambiguous failure the caller lists versions to prove
//     the outcome.
//   - Activate makes version the alias's active version; production follows
//     after a deployment window (ProdVersion).
//   - A method the API can't serve returns an apperr.NotFound error that says
//     so ("unsupported").
type Store interface {
	ListAliases(ctx context.Context) ([]LiveAlias, error)
	GetAlias(ctx context.Context, id int64) (LiveAlias, error)
	ListVersions(ctx context.Context, id int64) ([]AliasVersion, error)
	GetVersion(ctx context.Context, id int64, version string) (AliasVersion, error)
	CreateVersion(ctx context.Context, alias LiveAlias, entries []string, comment string) (AliasVersion, error)
	Activate(ctx context.Context, id int64, version string) error
	Deployment(ctx context.Context) (Deployment, error)
	Limits(ctx context.Context) ([]Limit, error)
	// DeployedRules returns the rules of the ACL version in production, or
	// none when nothing is deployed.
	DeployedRules(ctx context.Context) ([]ACLRule, error)
}

// OwnSpacePrefix is one own-space prefix and where it came from.
type OwnSpacePrefix struct {
	Prefix netip.Prefix
	Source string // "static", "alias <name>", "analytics <customer>/<site>"
}

// OwnSpaceSource supplies own-space prefixes beyond the desired file's
// static list and own-space aliases: the per-site protected prefixes from
// Prolexic Analytics.
type OwnSpaceSource func(ctx context.Context) ([]OwnSpacePrefix, error)
