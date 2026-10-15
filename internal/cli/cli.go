// Package cli is the prolexic command tree: Cobra commands, credential and
// client wiring, and the output contract (one Document on stdout, an error
// document on stderr, a stable exit code).
//
// A command is a constructor in the tree of root.go. It declares its flags
// on its cobra.Command and runs through app.run: the body does its work and
// returns a Document. It never writes to stdout itself. A command that
// produced a partial result returns both the document and an error: the
// document is printed and the error decides the exit code.
package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// Env is the process environment, injectable for tests.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Home           string // "" means os.UserHomeDir
	Now            func() time.Time
	Sleep          func(context.Context, time.Duration) error // nil means a real, cancellable sleep
	// Bogons overrides the bogon list (tests drop the documentation ranges
	// their fixtures use); nil means ncf.Bogons.
	Bogons []netip.Prefix

	// Transport and Scheme let tests point clients at an httptest server.
	Transport http.RoundTripper
	Scheme    string
}

// OSEnv is the real environment.
func OSEnv() Env {
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Now: time.Now}
}

// app is one invocation's state: the environment plus the common flags.
type app struct {
	env    Env
	format output.Format

	edgerc       string
	section      string
	writeSection string
	accountKey   string

	formatFlag string          // --format as given; parsed into format before a command runs
	doc        output.Document // what the command returned, printed by Run
	ran        bool            // a command body ran (so an error is its own, not a usage error)
}

// Run executes args and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Sleep == nil {
		env.Sleep = sleep
	}
	a := &app{env: env, format: output.Auto}
	if len(args) > 0 && args[0] == "--version" {
		args = append([]string{"version"}, args[1:]...)
	}
	err := a.execute(ctx, args)
	if doc := a.doc; doc != nil {
		if werr := output.Write(env.Stdout, a.format, doc); werr != nil && err == nil {
			err = werr
		}
	}
	if err != nil {
		return a.fail(err)
	}
	return exitCode(apperr.OK)
}

func (a *app) fail(err error) int {
	code := exitCode(apperr.KindOf(err))
	if werr := output.Write(a.env.Stderr, a.format, output.NewErrorDoc(err, code)); werr != nil {
		fmt.Fprintf(a.env.Stderr, "prolexic: %v\n", err)
	}
	return code
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// credentials resolves one section, applying --account-key.
func (a *app) credentials(section string) (edgegrid.Credentials, edgegrid.Source, error) {
	c, src, err := edgegrid.Load(edgegrid.Options{Section: section, Edgerc: a.edgerc, Getenv: a.env.Getenv, Home: a.env.Home})
	if err != nil {
		return c, src, err
	}
	if a.accountKey != "" {
		c.AccountKey = a.accountKey
	}
	return c, src, nil
}

// readClient is the API client for reads.
func (a *app) readClient() (*akamai.Client, error) {
	return a.client(a.section)
}

// writeClient is the API client for writes. Only apply may call it: CI hands
// the write credentials to the apply job alone.
func (a *app) writeClient() (*akamai.Client, error) {
	return a.client(a.writeSection)
}

func (a *app) client(section string) (*akamai.Client, error) {
	c, _, err := a.credentials(section)
	if err != nil {
		return nil, err
	}
	return akamai.New(c, akamai.Options{Base: a.env.Transport, Scheme: a.env.Scheme}), nil
}
