package ncf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// DesiredSchemaID names the desired file's format and its published schema.
const DesiredSchemaID = "prolexic.desired.v1"

// MaxFileSize bounds a desired file. The largest alias type holds 19,999
// entries; with metadata on every one that is well under this.
const MaxFileSize = 16 << 20

// File is the desired file. It is machine-owned: written only by export,
// add, remove and fmt, always in canonical form (see Canonical).
type File struct {
	JSONSchema string `json:"$schema,omitempty" doc:"Optional reference to this schema, for editor validation."`
	Schema     string `json:"schema" enum:"prolexic.desired.v1"`
	AccountID  string `json:"accountId" doc:"The Akamai account the aliases belong to."`
	// OwnSpace is our own address space: a deny entry must never cover it.
	OwnSpace OwnSpace `json:"ownSpace"`
	Aliases  []Alias  `json:"aliases"`
}

// OwnSpace lists our protected prefixes. Plan adds the per-site protected
// prefixes from Prolexic Analytics to these.
type OwnSpace struct {
	Prefixes []string `json:"prefixes" doc:"Static own-space prefixes."`
	Aliases  []string `json:"aliases" doc:"Names of live aliases whose entries are own space (the protected-destination alias)."`
}

// Role says which side of the firewall an alias's entries sit on. Own-space
// checks apply to deny-side aliases.
type Role string

const (
	RoleDeny  Role = "deny"
	RoleAllow Role = "allow"
)

// Valid reports whether r is a role an alias can have.
func (r Role) Valid() bool { return r == RoleDeny || r == RoleAllow }

// Alias is one managed alias: keyed by name, pinned by id, type asserted.
type Alias struct {
	Name    string  `json:"name"`
	ID      int64   `json:"id"`
	Type    string  `json:"type" enum:"SOURCE,BIG,DIPA"`
	Role    Role    `json:"role" enum:"deny,allow"`
	Entries []Entry `json:"entries"`
}

// DenySide reports whether the own-space check applies: a deny-role alias of
// source addresses. A DIPA alias lists destinations, our protected ones, so
// its entries are own space by definition whatever its role says.
func (a Alias) DenySide() bool { return a.Role == RoleDeny && a.Type != "DIPA" }

// Entry is an alias entry with optional metadata. In JSON it is a bare
// string when it has no metadata, otherwise an object with "cidr".
type Entry struct {
	CIDR    string `json:"cidr" doc:"A prefix, GEO::<country> or ASN::<number>."`
	Ticket  string `json:"ticket,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Added   string `json:"added,omitempty" doc:"YYYY-MM-DD."`
	Expires string `json:"expires,omitempty" doc:"YYYY-MM-DD; a warning once past."`
}

// HasMetadata reports whether e needs the object form.
func (e Entry) HasMetadata() bool {
	return e.Ticket != "" || e.Reason != "" || e.Added != "" || e.Expires != ""
}

type entryObject Entry // no methods: the plain struct encoding

func (e Entry) MarshalJSON() ([]byte, error) {
	if !e.HasMetadata() {
		return json.Marshal(e.CIDR)
	}
	return json.Marshal(entryObject(e))
}

func (e *Entry) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		*e = Entry{}
		return json.Unmarshal(b, &e.CIDR)
	}
	var o entryObject
	if err := strictUnmarshal(b, &o); err != nil {
		return fmt.Errorf("entry: %w", err)
	}
	if o.CIDR == "" {
		return errors.New(`entry: object form needs "cidr"`)
	}
	*e = Entry(o)
	return nil
}

// JSONSchema describes the union.
func (Entry) JSONSchema() map[string]any {
	date := map[string]any{"type": "string", "pattern": `^\d{4}-\d{2}-\d{2}$`}
	return map[string]any{"oneOf": []any{
		map[string]any{"type": "string", "description": "A prefix, GEO::<country> or ASN::<number>, without metadata."},
		map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"cidr"},
			"properties": map[string]any{
				"cidr":    map[string]any{"type": "string"},
				"ticket":  map[string]any{"type": "string"},
				"reason":  map[string]any{"type": "string"},
				"added":   date,
				"expires": date,
			},
		},
	}}
}

// Decode reads a desired file strictly: unknown fields, trailing data and
// oversize input are errors (exit 6). It checks only the encoding; Validate
// checks the content.
func Decode(r io.Reader) (*File, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.Usage, err, "read desired file")
	}
	if len(raw) > MaxFileSize {
		return nil, raw, apperr.New(apperr.Validation, "desired file is larger than %d bytes", MaxFileSize)
	}
	var f File
	if err := strictUnmarshal(raw, &f); err != nil {
		return nil, raw, apperr.Wrap(apperr.Validation, err, "decode desired file")
	}
	return &f, raw, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// Canonical is f's one serialisation: object keys sorted, aliases sorted by
// name, entries sorted by Compare (unparsable ones last, as written), list
// fields never null, two-space indentation and a trailing newline. A change
// of one entry is a one-entry diff.
func Canonical(f *File) ([]byte, error) {
	c := *f
	c.Aliases = slices.Clone(f.Aliases)
	slices.SortStableFunc(c.Aliases, func(a, b Alias) int { return strings.Compare(a.Name, b.Name) })
	for i := range c.Aliases {
		c.Aliases[i].Entries = sortEntries(c.Aliases[i].Entries)
	}
	c.OwnSpace.Prefixes = sortStrings(f.OwnSpace.Prefixes, true)
	c.OwnSpace.Aliases = sortStrings(f.OwnSpace.Aliases, false)
	if c.Aliases == nil {
		c.Aliases = []Alias{}
	}

	// Keys come in the structs' field order, which reads top-down in a diff:
	// each alias's name, id, type and role before its entries, and each
	// entry's cidr first.
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func sortEntries(in []Entry) []Entry {
	out := slices.Clone(in)
	if out == nil {
		return []Entry{}
	}
	for i := range out {
		if v, err := ParseAuthored(out[i].CIDR); err == nil {
			out[i].CIDR = v.String()
		}
	}
	slices.SortStableFunc(out, func(a, b Entry) int {
		va, ea := ParseAuthored(a.CIDR)
		vb, eb := ParseAuthored(b.CIDR)
		switch {
		case ea == nil && eb == nil:
			return Compare(va, vb)
		case ea == nil:
			return -1
		case eb == nil:
			return 1
		}
		return 0
	})
	return out
}

func sortStrings(in []string, prefixes bool) []string {
	out := slices.Clone(in)
	if out == nil {
		return []string{}
	}
	if !prefixes {
		slices.Sort(out)
		return out
	}
	for i := range out {
		if v, err := ParseAuthored(out[i]); err == nil {
			out[i] = v.String()
		}
	}
	slices.SortStableFunc(out, func(a, b string) int {
		va, ea := ParseAuthored(a)
		vb, eb := ParseAuthored(b)
		if ea == nil && eb == nil {
			return Compare(va, vb)
		}
		return strings.Compare(a, b)
	})
	return out
}

// ParseDate parses a metadata date (YYYY-MM-DD).
func ParseDate(s string) (time.Time, error) {
	return time.Parse(time.DateOnly, s)
}
