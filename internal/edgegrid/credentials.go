// Package edgegrid resolves Akamai EdgeGrid credentials and signs requests
// with them (EG1-HMAC-SHA256).
//
// Credentials come from the environment first, then from an .edgerc file.
// For section "default" the variables are AKAMAI_HOST, AKAMAI_CLIENT_TOKEN,
// AKAMAI_CLIENT_SECRET and AKAMAI_ACCESS_TOKEN (plus optional
// AKAMAI_MAX_BODY and AKAMAI_ACCOUNT_KEY); for any other section they carry
// its upper-cased name, e.g. AKAMAI_WRITE_HOST. This matches Akamai's own
// clients.
//
// Nothing in this package logs or formats a secret: Credentials has no
// String method that reveals one, and Source describes where credentials
// came from without their values.
package edgegrid

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// DefaultMaxBody is how much of a POST body is hashed when the credentials
// don't say.
const DefaultMaxBody = 131072

// Credentials are one API client's EdgeGrid credentials.
type Credentials struct {
	Host         string // bare host name, no scheme or path
	ClientToken  string
	ClientSecret string
	AccessToken  string
	MaxBody      int
	AccountKey   string // optional accountSwitchKey
}

// String never reveals a secret.
func (c Credentials) String() string { return "edgegrid.Credentials{" + c.Host + "}" }

// GoString keeps %#v from printing secrets too.
func (c Credentials) GoString() string { return c.String() }

// Source says where credentials were found, without their values.
type Source struct {
	Kind    string   `json:"kind" enum:"env,edgerc"`
	Section string   `json:"section"`
	Path    string   `json:"path,omitempty" doc:"The .edgerc file, for kind edgerc."`
	Vars    []string `json:"vars,omitempty" doc:"The environment variables read, for kind env."`
}

// Options select credentials.
type Options struct {
	Section string              // "" means "default"
	Edgerc  string              // "" means ~/.edgerc
	Getenv  func(string) string // nil means os.Getenv
	Home    string              // "" means os.UserHomeDir
}

var fields = []string{"host", "client_token", "client_secret", "access_token"}

// Load resolves credentials for a section: the environment if any of its
// variables are set, otherwise the .edgerc file.
func Load(opts Options) (Credentials, Source, error) {
	section := opts.Section
	if section == "" {
		section = "default"
	}
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	if c, src, ok, err := fromEnv(section, getenv); ok || err != nil {
		return c, src, err
	}

	path, err := edgercPath(opts)
	if err != nil {
		return Credentials{}, Source{}, err
	}
	values, err := readSection(path, section)
	if err != nil {
		return Credentials{}, Source{}, err
	}
	c, err := build(values, func(k string) string { return fmt.Sprintf("%s in [%s] of %s", k, section, path) })
	if err != nil {
		return Credentials{}, Source{}, err
	}
	return c, Source{Kind: "edgerc", Section: section, Path: path}, nil
}

func envPrefix(section string) string {
	if section == "default" {
		return "AKAMAI_"
	}
	s := strings.ToUpper(section)
	s = strings.NewReplacer("-", "_", ".", "_").Replace(s)
	return "AKAMAI_" + s + "_"
}

func fromEnv(section string, getenv func(string) string) (Credentials, Source, bool, error) {
	prefix := envPrefix(section)
	values := map[string]string{}
	var vars []string
	for _, k := range append(fields, "max_body", "account_key") {
		name := prefix + strings.ToUpper(k)
		if v := getenv(name); v != "" {
			values[k] = v
			vars = append(vars, name)
		}
	}
	any := false
	for _, k := range fields {
		if values[k] != "" {
			any = true
		}
	}
	if !any {
		return Credentials{}, Source{}, false, nil
	}
	// Partly set is an error, not a fallback: falling through to .edgerc
	// would silently use a different client than the one CI meant.
	c, err := build(values, func(k string) string { return prefix + strings.ToUpper(k) })
	if err != nil {
		return Credentials{}, Source{}, true, err
	}
	return c, Source{Kind: "env", Section: section, Vars: vars}, true, nil
}

func build(values map[string]string, name func(string) string) (Credentials, error) {
	var missing []string
	for _, k := range fields {
		if values[k] == "" {
			missing = append(missing, name(k))
		}
	}
	if len(missing) > 0 {
		return Credentials{}, apperr.New(apperr.Credentials, "missing %s", strings.Join(missing, ", "))
	}
	c := Credentials{
		Host:         normalizeHost(values["host"]),
		ClientToken:  values["client_token"],
		ClientSecret: values["client_secret"],
		AccessToken:  values["access_token"],
		AccountKey:   values["account_key"],
		MaxBody:      DefaultMaxBody,
	}
	if v := values["max_body"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Credentials{}, apperr.New(apperr.Credentials, "%s is not a positive integer", name("max_body"))
		}
		c.MaxBody = n
	}
	return c, nil
}

func normalizeHost(h string) string {
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	h, _, _ = strings.Cut(h, "/")
	return h
}

func edgercPath(opts Options) (string, error) {
	if opts.Edgerc != "" {
		return opts.Edgerc, nil
	}
	home := opts.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", apperr.Wrap(apperr.Credentials, err, "no home directory for ~/.edgerc")
		}
		home = h
	}
	return filepath.Join(home, ".edgerc"), nil
}

// readSection parses one section of an INI-style .edgerc. Keys are
// lower-cased and "max-body" is accepted for "max_body"; values may be
// quoted.
func readSection(path, section string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, apperr.New(apperr.Credentials, "no credentials: no environment variables for section %q and no %s", section, path)
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.Credentials, err, "open %s", path)
	}
	defer f.Close()

	values := map[string]string{}
	found, in := false, false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			in = strings.TrimSpace(line[1:len(line)-1]) == section
			found = found || in
			continue
		}
		if !in {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), "-", "_")
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		values[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, apperr.Wrap(apperr.Credentials, err, "read %s", path)
	}
	if !found {
		return nil, apperr.New(apperr.Credentials, "no section [%s] in %s", section, path)
	}
	return values, nil
}
