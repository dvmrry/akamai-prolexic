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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/output"
	"github.com/dvmrry/akamai-prolexic/internal/version"
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
	caBundle     string // --ca-bundle: extra root CAs (a TLS-inspecting proxy's)

	rootCAs    *x509.CertPool // loaded from caBundle on first use
	rootCAsErr error
	rootCAsN   int
	loadedCAs  bool

	formatFlag   string          // --format as given; parsed into format before a command runs
	formatChosen bool            // --format or PROLEXIC_FORMAT was given, not the default
	doc          output.Document // what the command returned, printed by Run
	ran          bool            // a command body ran (so an error is its own, not a usage error)
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
	a.presetFormat(args) // so errors before flag parsing still honour an explicit choice
	if len(args) > 0 && args[0] == "--version" {
		args = append([]string{"version"}, args[1:]...)
	}
	err := a.execute(ctx, args)
	if doc := a.doc; doc != nil {
		output.Stamp(doc, env.Now(), version.Current().Version)
		if werr := output.Write(env.Stdout, a.format, doc); werr != nil && err == nil {
			err = werr
		}
	}
	if err != nil {
		return a.fail(err)
	}
	return exitCode(apperr.OK)
}

// fail reports err on stderr and returns its exit code. stderr is for people
// (a CI log, a terminal), so the error is one text line unless JSON was asked
// for explicitly (--format json or PROLEXIC_FORMAT=json); the stdout
// document and the exit code are the contract.
func (a *app) fail(err error) int {
	code := exitCode(apperr.KindOf(err))
	format := output.Text
	if a.formatChosen && a.format == output.JSON {
		format = output.JSON
	}
	ed := output.NewErrorDoc(err, code)
	output.Stamp(ed, a.env.Now(), version.Current().Version)
	if werr := output.Write(a.env.Stderr, format, ed); werr != nil {
		fmt.Fprintf(a.env.Stderr, "prolexic: %s\n", output.Sanitize(err.Error()))
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

// readClient is the API client for reads. It is read-only: it refuses any
// request that isn't a read, before sending it.
func (a *app) readClient() (*akamai.Client, error) {
	return a.client(a.section, true)
}

// writeClient is the API client for writes. Only apply may call it: CI hands
// the write credentials to the apply job alone.
func (a *app) writeClient() (*akamai.Client, error) {
	return a.client(a.writeSection, false)
}

func (a *app) client(section string, readOnly bool) (*akamai.Client, error) {
	c, _, err := a.credentials(section)
	if err != nil {
		return nil, err
	}
	pool, _, err := a.loadRootCAs()
	if err != nil {
		return nil, err
	}
	return akamai.New(c, akamai.Options{Base: a.env.Transport, Scheme: a.env.Scheme, ReadOnly: readOnly, RootCAs: pool}), nil
}

// loadRootCAs returns the system roots plus --ca-bundle's certificates, and
// how many it added; nil when no bundle is declared. A bundle that can't be
// read or holds no certificate is an error, never silently ignored.
func (a *app) loadRootCAs() (*x509.CertPool, int, error) {
	if a.loadedCAs {
		return a.rootCAs, a.rootCAsN, a.rootCAsErr
	}
	a.loadedCAs = true
	if a.caBundle == "" {
		return nil, 0, nil
	}
	a.rootCAs, a.rootCAsN, a.rootCAsErr = loadCABundle(a.caBundle)
	return a.rootCAs, a.rootCAsN, a.rootCAsErr
}

func loadCABundle(path string) (*x509.CertPool, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, apperr.New(apperr.Usage, "--ca-bundle %s: %v", path, fsErr(err))
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	n := 0
	for block, rest := pem.Decode(b); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, apperr.New(apperr.Usage, "--ca-bundle %s: certificate %d: %v", path, n+1, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, 0, apperr.New(apperr.Usage, "--ca-bundle %s holds no PEM certificate", path)
	}
	return pool, n, nil
}

// presetFormat reads an explicit format choice (--format or PROLEXIC_FORMAT)
// before cobra parses anything, so an error raised during parsing (an
// unknown flag, a wrong argument count) still honours it. The parsed flag
// replaces it once parsing succeeds.
func (a *app) presetFormat(args []string) {
	v := a.env.Getenv("PROLEXIC_FORMAT")
	for i, s := range args {
		if s == "--" {
			break
		}
		if s == "--format" && i+1 < len(args) {
			v = args[i+1]
		} else if after, ok := strings.CutPrefix(s, "--format="); ok {
			v = after
		}
	}
	if f, err := output.ParseFormat(v); v != "" && err == nil {
		a.format, a.formatChosen = f, true
	}
}
