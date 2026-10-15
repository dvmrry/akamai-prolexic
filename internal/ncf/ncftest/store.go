// Package ncftest is an in-memory ncf.Store with versioned aliases and
// injectable faults, for testing plan and apply without the API.
package ncftest

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

// Store models the NCF v2 behaviour the brief describes: every write is a
// new version, activation is separate, and production follows activation
// after ProdLag polls.
type Store struct {
	mu      sync.Mutex
	aliases map[int64]*alias

	// ProdLag is how many alias reads (GetAlias or ListAliases) an
	// activation takes to reach production.
	ProdLag int
	// Deploy is what Deployment returns.
	Deploy ncf.Deployment
	// Unversioned makes the store behave like NCF v1: no version fields,
	// and version methods unsupported.
	Unversioned bool

	// CreateErr, when set, is returned by CreateVersion. CreateLands says
	// whether the version is created anyway (an ambiguous failure that
	// landed).
	CreateErr   error
	CreateLands bool
	// ActivateErr, when set, is returned by Activate; ActivateLands says
	// whether the activation took effect anyway.
	ActivateErr   error
	ActivateLands bool
	// Corrupt, when set, rewrites the entries a created version stores.
	Corrupt func([]string) []string
	// ActivateFails makes activating a new version of the given aliases
	// fail (re-activating the current one still works, for rollbacks).
	ActivateFails map[int64]error
	// GetVersionErr, when set, is returned by GetVersion.
	GetVersionErr error
	// BigActivates makes a BIG alias's new version active on creation, as
	// the multipart upload may.
	BigActivates bool
	// Comments records each CreateVersion comment.
	Comments []string
	// BeforeCreate runs at the start of CreateVersion (e.g. to simulate a
	// concurrent writer).
	BeforeCreate func(*Store)

	// Calls records method names in order.
	Calls []string
}

type alias struct {
	live     ncf.LiveAlias
	versions [][]string // versions[i] is version i+1
	lag      int        // polls left before production catches up
	pending  string     // version heading to production
	unused   bool       // no deployed rule references it: no production version
}

// versionID names version n (1-based) the way live NCF v2 does: "V1", "V2".
func versionID(n int) string { return fmt.Sprintf("V%d", n) }

// versionIndex is versionID's inverse as a slice index; -1 if malformed.
func versionIndex(id string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "V"))
	if err != nil || !strings.HasPrefix(id, "V") {
		return -1
	}
	return n - 1
}

// New returns an empty store.
func New() *Store { return &Store{aliases: map[int64]*alias{}} }

// Add creates an alias whose version 1 holds entries, active and in
// production.
func (s *Store) Add(l ncf.LiveAlias, entries ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.ActiveVersion, l.ProdVersion = "V1", "V1"
	s.aliases[l.ID] = &alias{live: l, versions: [][]string{slices.Clone(entries)}}
}

// Unused marks an alias as referenced by no deployed rule: it has no
// production version, before or after an activation.
func (s *Store) Unused(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aliases[id].unused = true
}

// AddVersions appends n inactive versions (a concurrent writer).
func (s *Store) AddVersions(id int64, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.aliases[id]
	for range n {
		a.versions = append(a.versions, slices.Clone(a.versions[len(a.versions)-1]))
	}
}

// Activate is exported for tests that simulate an out-of-band change.
func (s *Store) ActivateNow(id int64, entries ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.aliases[id]
	a.versions = append(a.versions, slices.Clone(entries))
	a.live.ActiveVersion = versionID(len(a.versions))
	a.live.ProdVersion = versionID(len(a.versions))
}

// Live returns an alias's current state, entries from its active version.
func (s *Store) Live(id int64) ncf.LiveAlias {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot(s.aliases[id], true)
}

// tick moves a pending activation one read closer to production.
func (a *alias) tick() {
	if a.pending == "" || a.unused {
		return
	}
	if a.lag <= 0 {
		a.live.ProdVersion, a.pending = a.pending, ""
	} else {
		a.lag--
	}
}

func (s *Store) snapshot(a *alias, entries bool) ncf.LiveAlias {
	l := a.live
	act := a.versions[versionIndex(l.ActiveVersion)]
	l.EntriesCount = len(act)
	l.Entries = nil
	if entries {
		l.Entries = slices.Clone(act)
	}
	if a.unused {
		l.ProdVersion = ""
	}
	if s.Unversioned {
		l.ActiveVersion, l.ProdVersion = "", ""
	}
	return l
}

func (s *Store) record(name string) { s.Calls = append(s.Calls, name) }

var unsupported = apperr.New(apperr.NotFound, "unsupported by this API version")

func notFound(id int64) error { return apperr.New(apperr.NotFound, "no alias %d", id) }

func (s *Store) ListAliases(context.Context) ([]ncf.LiveAlias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("ListAliases")
	var out []ncf.LiveAlias
	for _, a := range s.aliases {
		a.tick()
		out = append(out, s.snapshot(a, false))
	}
	slices.SortFunc(out, func(x, y ncf.LiveAlias) int { return int(x.ID - y.ID) })
	return out, nil
}

func (s *Store) GetAlias(_ context.Context, id int64) (ncf.LiveAlias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("GetAlias")
	a, ok := s.aliases[id]
	if !ok {
		return ncf.LiveAlias{}, notFound(id)
	}
	a.tick()
	return s.snapshot(a, true), nil
}

func (s *Store) ListVersions(_ context.Context, id int64) ([]ncf.AliasVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("ListVersions")
	if s.Unversioned {
		return nil, unsupported
	}
	a, ok := s.aliases[id]
	if !ok {
		return nil, notFound(id)
	}
	out := make([]ncf.AliasVersion, len(a.versions))
	for i := range a.versions {
		out[i] = ncf.AliasVersion{Version: versionID(i + 1), Active: versionID(i+1) == a.live.ActiveVersion}
	}
	return out, nil
}

func (s *Store) GetVersion(_ context.Context, id int64, v string) (ncf.AliasVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("GetVersion")
	if s.GetVersionErr != nil {
		return ncf.AliasVersion{}, s.GetVersionErr
	}
	if s.Unversioned {
		return ncf.AliasVersion{}, unsupported
	}
	a, ok := s.aliases[id]
	i := versionIndex(v)
	if !ok || i < 0 || i >= len(a.versions) {
		return ncf.AliasVersion{}, notFound(id)
	}
	return ncf.AliasVersion{Version: v, Active: v == a.live.ActiveVersion, Entries: slices.Clone(a.versions[i])}, nil
}

func (s *Store) CreateVersion(_ context.Context, l ncf.LiveAlias, entries []string, comment string) (ncf.AliasVersion, error) {
	if s.BeforeCreate != nil {
		s.BeforeCreate(s)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("CreateVersion")
	if s.Unversioned {
		return ncf.AliasVersion{}, unsupported
	}
	a, ok := s.aliases[l.ID]
	if !ok {
		return ncf.AliasVersion{}, notFound(l.ID)
	}
	s.Comments = append(s.Comments, comment)
	if s.CreateErr != nil && !s.CreateLands {
		return ncf.AliasVersion{}, s.CreateErr
	}
	stored := slices.Clone(entries)
	if s.Corrupt != nil {
		stored = s.Corrupt(stored)
	}
	a.versions = append(a.versions, stored)
	v := versionID(len(a.versions))
	active := s.BigActivates && a.live.Type == "BIG"
	if active {
		a.live.ActiveVersion, a.pending, a.lag = v, v, s.ProdLag
	}
	if s.CreateErr != nil {
		return ncf.AliasVersion{}, s.CreateErr
	}
	return ncf.AliasVersion{Version: v, Active: active}, nil
}

func (s *Store) Activate(_ context.Context, id int64, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("Activate")
	if s.Unversioned {
		return unsupported
	}
	a, ok := s.aliases[id]
	if !ok {
		return notFound(id)
	}
	if err, ok := s.ActivateFails[id]; ok && v != a.live.ActiveVersion {
		return err
	}
	if s.ActivateErr != nil && !s.ActivateLands {
		return s.ActivateErr
	}
	a.live.ActiveVersion, a.pending, a.lag = v, v, s.ProdLag
	return s.ActivateErr
}

func (s *Store) Deployment(context.Context) (ncf.Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record("Deployment")
	return s.Deploy, nil
}

func (s *Store) Limits(context.Context) ([]ncf.Limit, error) {
	s.record("Limits")
	return []ncf.Limit{{Type: "SOURCE", Limit: 100}, {Type: "BIG", Limit: 10}, {Type: "DIPA", Limit: 100}}, nil
}

// Count returns how many times method was called.
func (s *Store) Count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.Calls {
		if c == method {
			n++
		}
	}
	return n
}
