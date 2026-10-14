package ncf

import (
	"context"
	"net/netip"
)

// MaxVersions is how many versions an alias can ever have. Versions cannot
// be deleted; every apply spends one.
const MaxVersions = 10

// LiveAlias is an alias as the API reports it.
type LiveAlias struct {
	ID        int64
	Name      string
	Type      string // SOURCE, BIG or DIPA
	IPVersion string // V4 or V6
	Editable  bool   // isCustomerEditable; false means Akamai-managed
	AccountID string

	// ActiveVersion is the plan-time conflict token. ProdVersion is the
	// version production carries. Versions is how many versions exist.
	// All three are 0 when the API doesn't expose versions (NCF v1).
	ActiveVersion int
	ProdVersion   int
	Versions      int

	EntriesCount int
	// Entries is nil unless fetched with GetAlias. Never fetch them for an
	// Akamai-managed alias.
	Entries []string
}

// AliasVersion is one version of an alias.
type AliasVersion struct {
	Version int
	// Entries is nil unless fetched with GetVersion.
	Entries []string
}

// Deployment is the account's ACL deployment state.
type Deployment struct {
	Version     int    // the ACL version in production
	State       string // PRODUCTION, PROCESSING or FAILED
	FailedRules int    // rules that failed to install; non-zero is a partial failure
	Processing  bool   // a version is being staged
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
//   - CreateVersion creates an inactive version holding exactly entries,
//     using the multipart upload for BIG aliases. It is never retried: on an
//     ambiguous failure the caller lists versions to prove the outcome.
//   - Activate makes version the alias's active version; production follows
//     after a deployment window (ProdVersion).
//   - A method the API can't serve returns an apperr.NotFound error that says
//     so ("unsupported").
type Store interface {
	ListAliases(ctx context.Context) ([]LiveAlias, error)
	GetAlias(ctx context.Context, id int64) (LiveAlias, error)
	ListVersions(ctx context.Context, id int64) ([]AliasVersion, error)
	GetVersion(ctx context.Context, id int64, version int) (AliasVersion, error)
	CreateVersion(ctx context.Context, alias LiveAlias, entries []string) (int, error)
	Activate(ctx context.Context, id int64, version int) error
	Deployment(ctx context.Context) (Deployment, error)
	Limits(ctx context.Context) ([]Limit, error)
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
