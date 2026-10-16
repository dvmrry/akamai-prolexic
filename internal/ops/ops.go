// Package ops holds the operations: one per command, typed input to a
// Document. Every front (the CLI, an MCP server) calls them, so customer
// names are resolved, failures reported, rows sorted and inputs checked the
// same way whoever asks. Fronts parse their own input format, build a
// Runtime, call an operation and render what it returns.
//
// Messages here name fields, not any front's flags: an MCP client never
// typed --since.
package ops

import (
	"context"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfanalytics"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/networkhealth"
)

// Runtime is what operations need from a front: API clients, a clock, and
// where progress goes. The CLI builds one per invocation.
type Runtime struct {
	// ReadClient builds a client over the read credentials; it must refuse
	// writes. WriteClient builds one over the write credentials, for apply
	// only; nil means this front can't write.
	ReadClient  func() (*akamai.Client, error)
	WriteClient func() (*akamai.Client, error)
	// Now and Sleep are the clock; nil means real time.
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
	// Progress hears each step of a long operation (apply, a waiting
	// check), so a front can show a long wait isn't a hang; nil is silent.
	Progress func(string)
	// Bogons overrides ncf.Bogons; nil means the default. Tests drop the
	// documentation ranges their fixtures use.
	Bogons []netip.Prefix
	// Dir is where relative file paths in inputs resolve; empty means the
	// process's working directory. Documents show paths as given, so a
	// front can keep them relative (a saved plan then names no local
	// directory).
	Dir string
}

// abs is path as the operation opens it: relative to Dir when set. ""
// stays "", for the operation to report as missing.
func (r *Runtime) abs(path string) string {
	if path == "" || r.Dir == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(r.Dir, path)
}

func (r *Runtime) now() time.Time {
	if r.Now == nil {
		return time.Now()
	}
	return r.Now()
}

func (r *Runtime) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r *Runtime) progress(msg string) {
	if r.Progress != nil {
		r.Progress(msg)
	}
}

// analytics is the Prolexic Analytics client, over the read credentials.
func (r *Runtime) analytics() (*analytics.Client, error) {
	c, err := r.ReadClient()
	if err != nil {
		return nil, err
	}
	return analytics.New(c), nil
}

// networkHealth is the Network Health client, over the read credentials.
func (r *Runtime) networkHealth() (*networkhealth.Client, error) {
	c, err := r.ReadClient()
	if err != nil {
		return nil, err
	}
	return networkhealth.New(c), nil
}

// ncfV2 is the concrete NCF v2 client over the read credentials, for the
// reads that go beyond ncf.Store.
func (r *Runtime) ncfV2() (*ncfapi.V2, error) {
	c, err := r.ReadClient()
	if err != nil {
		return nil, err
	}
	return ncfapi.NewV2(c), nil
}

// ncfRead is the NCF store over the read credentials.
func (r *Runtime) ncfRead() (ncf.Store, error) {
	v, err := r.ncfV2()
	if err != nil {
		return nil, err
	}
	return v, nil
}

// checker is the offline checker as of now.
func (r *Runtime) checker() *ncf.Checker {
	c := ncf.NewChecker(r.now())
	if r.Bogons != nil {
		c.Bogons = r.Bogons
	}
	return c
}

// planOptions are the plan options: live own space from Prolexic Analytics
// (ncfanalytics), unless skipLiveOwnSpace.
func (r *Runtime) planOptions(maxRemovals int, skipLiveOwnSpace bool) ncf.PlanOptions {
	if skipLiveOwnSpace {
		return ncf.PlanOptions{MaxRemovals: maxRemovals, SkipLiveOwnSpace: true}
	}
	return ncf.PlanOptions{MaxRemovals: maxRemovals, LiveOwnSpace: ncfanalytics.Source(r.analytics)}
}
