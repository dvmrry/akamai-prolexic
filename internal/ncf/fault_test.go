package ncf_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncftest"
)

// faultMode is how the injected write fails.
type faultMode string

const (
	failClean  faultMode = "clean"  // refused: nothing happened
	failLost   faultMode = "lost"   // ambiguous, and it didn't land
	failLanded faultMode = "landed" // ambiguous, and it did land
)

// faultStore fails the failAt-th write (CreateVersion or Activate, rollback
// re-activations included) in the given mode. Reads pass through.
type faultStore struct {
	*ncftest.Store
	failAt, writes int
	mode           faultMode
}

func (f *faultStore) inject(do func() error) error {
	f.writes++
	if f.writes != f.failAt {
		return do()
	}
	switch f.mode {
	case failClean:
		return &apperr.Error{Kind: apperr.Upstream, Message: "injected: refused", Upstream: &apperr.UpstreamDetail{Status: 400}}
	case failLost:
		return ambiguous
	default:
		if err := do(); err != nil {
			return err
		}
		return ambiguous
	}
}

func (f *faultStore) CreateVersion(ctx context.Context, l ncf.LiveAlias, entries []string, comment string) (ncf.AliasVersion, error) {
	var v ncf.AliasVersion
	err := f.inject(func() (err error) { v, err = f.Store.CreateVersion(ctx, l, entries, comment); return err })
	if err != nil && f.writes == f.failAt && f.mode != failLanded {
		return ncf.AliasVersion{}, err
	}
	return v, err
}

func (f *faultStore) Activate(ctx context.Context, id int64, v string) error {
	return f.inject(func() error { return f.Store.Activate(ctx, id, v) })
}

// twoAliasWorld has two deny aliases that one apply changes together, so
// all-or-nothing is observable. The second is SOURCE, or BIG (at least 51
// entries; its upload goes live on arrival).
func twoAliasWorld(secondType string) (s *ncftest.Store, f *ncf.File, before, want map[int64][]string) {
	var from, to []string
	switch secondType {
	case "BIG":
		for i := 100; i < 160; i++ {
			from = append(from, fmt.Sprintf("198.51.100.%d", i))
		}
		to = append(slices.Clone(from[1:]), "198.51.100.160") // one out, one in
	default:
		from, to = []string{"198.51.100.200"}, []string{"198.51.100.200", "198.51.100.201"}
	}
	s = world()
	s.BigActivates = true
	s.Add(ncf.LiveAlias{ID: 103, Name: "block-b", Type: secondType, IPVersion: "V4", Editable: true, AccountID: "A-EXAMPLE"}, from...)
	f = desired("192.0.2.0/25", "198.51.100.9")
	f.Aliases = append(f.Aliases, ncf.Alias{Name: "block-b", ID: 103, Type: secondType, Role: ncf.RoleDeny, Entries: entries(to...)})
	before = map[int64][]string{101: {"192.0.2.0/25", "198.51.100.7"}, 103: from}
	want = map[int64][]string{101: {"192.0.2.0/25", "198.51.100.9"}, 103: to}
	return s, f, before, want
}

// TestApplyFaultAtEveryWrite fails each write of an apply in turn, in each
// mode, then re-runs it cleanly. After the failure: every changed alias is
// all old or all new (unless the error says to check by hand), and no alias
// has gained a second version. After the re-run: the change has landed,
// still with at most one new version per alias.
func TestApplyFaultAtEveryWrite(t *testing.T) {
	for _, second := range []string{"SOURCE", "BIG"} {
		for _, mode := range []faultMode{failClean, failLost, failLanded} {
			for at := 1; at <= 8; at++ {
				t.Run(fmt.Sprintf("%s %s at write %d", second, mode, at), func(t *testing.T) {
					s, f, before, want := twoAliasWorld(second)
					versions := map[int64]int{}
					for id := range before {
						vs, _ := s.ListVersions(context.Background(), id)
						versions[id] = len(vs)
					}
					fs := &faultStore{Store: s, failAt: at, mode: mode}
					p := plan(t, s, f, defaults)
					opts := ncf.ApplyOptions{PlanOptions: defaults, ExpectDigest: p.Digest}
					_, _, err := checker().Apply(context.Background(), s, fs, f, nil, opts)

					// An alias may gain one new version. A retried BIG upload is the
					// documented exception: it carries no marker, so a re-run can't
					// recognise its earlier version and uploads once more
					// (docs/design.md, Plan and apply).
					newVersions := func(retried bool) {
						t.Helper()
						for id, n := range versions {
							limit := 1
							if retried && id == 103 && second == "BIG" {
								limit = 2
							}
							if vs, _ := s.ListVersions(context.Background(), id); len(vs)-n > limit {
								t.Errorf("alias %d gained %d versions; a create must never be repeated", id, len(vs)-n)
							}
						}
					}
					newVersions(false)
					if err != nil {
						changed := 0
						for id, w := range want {
							if ncf.SameEntries(s.Live(id).Entries, w) {
								changed++
							} else if !ncf.SameEntries(s.Live(id).Entries, before[id]) {
								t.Errorf("alias %d is neither old nor new: %v", id, s.Live(id).Entries)
							}
						}
						if changed == 1 && !strings.Contains(err.Error(), "by hand") {
							t.Errorf("half the change is live, and the error doesn't say so: %v", err)
						}
					}

					// A clean re-run of a fresh plan converges.
					p = plan(t, s, f, defaults)
					opts.ExpectDigest = p.Digest
					if _, _, err := checker().Apply(context.Background(), s, s, f, nil, opts); err != nil {
						t.Fatalf("re-run after %v: %v", err, err)
					}
					for id, w := range want {
						if l := s.Live(id); !ncf.SameEntries(l.Entries, w) || l.ProdVersion != l.ActiveVersion {
							t.Errorf("after the re-run alias %d is %v (active %s, prod %s)", id, l.Entries, l.ActiveVersion, l.ProdVersion)
						}
					}
					newVersions(true)
				})
			}
		}
	}
}
