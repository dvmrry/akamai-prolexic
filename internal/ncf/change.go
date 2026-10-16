package ncf

import (
	"bytes"
	"slices"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// AddRequest adds entries, with their metadata, to one alias.
type AddRequest struct {
	Alias   string
	Entries []string // as authored: a prefix, an address, GEO::<country> or ASN::<number>
	Ticket  string   // the ticket authorising the change; required
	Reason  string   // why; required
	Expires string   // YYYY-MM-DD after which the entries are flagged; optional
}

// RemoveRequest removes entries from one alias.
type RemoveRequest struct {
	Alias   string
	Entries []string
	Ticket  string // the ticket authorising the change; required
}

// Change is a proposed edit to the desired file: the file with the change
// made, the entries it added or removed, and the findings that decide
// whether it may be written. The file the change was made from is untouched.
type Change struct {
	File    *File
	Alias   string
	Entries []Entry // added, with their metadata; or removed, with the metadata they had
	// Findings are the change's own (entries already present, missing or
	// unreadable; a hand-edited file) and the whole changed file's
	// validation.
	Findings []Finding
	added    map[string]bool
}

// Blocked reports whether the change must not be written: any error, or a
// warning about an entry being added, so nothing new goes in with a question
// over it. A warning about an entry already in the file doesn't block.
func (ch *Change) Blocked() bool {
	return slices.ContainsFunc(ch.Findings, func(x Finding) bool {
		return x.Severity == Error || (x.Alias == ch.Alias && ch.added[x.Entry])
	})
}

// AddEntries proposes adding req's entries to f, stamped with req's ticket,
// reason and expiry and today's date. raw is the file as read: a file that
// isn't in canonical form was hand-edited, which blocks the change. Malformed
// requests are errors; problems with the entries are findings.
func (c *Checker) AddEntries(f *File, raw []byte, req AddRequest) (*Change, error) {
	if err := required(req.Entries, "ticket", req.Ticket, "reason", req.Reason); err != nil {
		return nil, err
	}
	if req.Expires != "" {
		if _, err := ParseDate(req.Expires); err != nil {
			return nil, apperr.New(apperr.Usage, "expiry %q is not YYYY-MM-DD", req.Expires)
		}
	}
	ch, alias, err := c.change(f, raw, req.Alias)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, e := range alias.Entries {
		if v, err := ParseAuthored(e.CIDR); err == nil {
			have[v.String()] = true
		}
	}
	today := c.Today.Format(time.DateOnly)
	for _, s := range req.Entries {
		v, err := ParseAuthored(s)
		if err != nil {
			ch.Findings = append(ch.Findings, Finding{Error, "entry", alias.Name, s, err.Error()})
			continue
		}
		key := v.String()
		if have[key] || ch.added[key] {
			ch.Findings = append(ch.Findings, Finding{Error, "already_present", alias.Name, key, key + " is already in the alias"})
			continue
		}
		ch.added[key] = true
		e := Entry{CIDR: key, Ticket: req.Ticket, Reason: req.Reason, Added: today, Expires: req.Expires}
		alias.Entries = append(alias.Entries, e)
		ch.Entries = append(ch.Entries, e)
	}
	ch.Findings = append(ch.Findings, c.Validate(ch.File, nil)...)
	return ch, nil
}

// RemoveEntries proposes removing req's entries from f, matched however
// they are written (198.51.100.7 is 198.51.100.7/32). The removed entries
// keep the metadata they had, for the record.
func (c *Checker) RemoveEntries(f *File, raw []byte, req RemoveRequest) (*Change, error) {
	if err := required(req.Entries, "ticket", req.Ticket); err != nil {
		return nil, err
	}
	ch, alias, err := c.change(f, raw, req.Alias)
	if err != nil {
		return nil, err
	}
	for _, s := range req.Entries {
		v, err := ParseAuthored(s)
		if err != nil {
			ch.Findings = append(ch.Findings, Finding{Error, "entry", alias.Name, s, err.Error()})
			continue
		}
		key := v.String()
		i := slices.IndexFunc(alias.Entries, func(e Entry) bool {
			w, err := ParseAuthored(e.CIDR)
			return err == nil && w.String() == key
		})
		if i < 0 {
			ch.Findings = append(ch.Findings, Finding{Error, "not_present", alias.Name, key, key + " is not in the alias"})
			continue
		}
		ch.Entries = append(ch.Entries, alias.Entries[i])
		alias.Entries = slices.Delete(alias.Entries, i, i+1)
	}
	ch.Findings = append(ch.Findings, c.Validate(ch.File, nil)...)
	return ch, nil
}

// change starts a Change on a copy of f, returning the copy's alias to edit.
func (c *Checker) change(f *File, raw []byte, name string) (*Change, *Alias, error) {
	g := *f
	g.Aliases = slices.Clone(f.Aliases)
	i := slices.IndexFunc(g.Aliases, func(a Alias) bool { return a.Name == name })
	if i < 0 {
		return nil, nil, apperr.New(apperr.Validation, "no alias %q in the desired file", name)
	}
	g.Aliases[i].Entries = slices.Clone(g.Aliases[i].Entries)
	ch := &Change{File: &g, Alias: name, Entries: []Entry{}, Findings: []Finding{}, added: map[string]bool{}}
	if pre, _, err := Decode(bytes.NewReader(raw)); err == nil {
		if canon, err := Canonical(pre); err == nil && !bytes.Equal(canon, raw) {
			ch.Findings = append(ch.Findings, Finding{Severity: Error, Code: "not_canonical", Message: "the file was hand-edited (not canonical); run prolexic fmt and review before changing it"})
		}
	}
	return ch, &g.Aliases[i], nil
}

// required refuses a request with no entries or a blank required field,
// given as name, value pairs.
func required(entries []string, fields ...string) error {
	if len(entries) == 0 {
		return apperr.New(apperr.Usage, "no entries to change")
	}
	for i := 0; i < len(fields); i += 2 {
		if strings.TrimSpace(fields[i+1]) == "" {
			return apperr.New(apperr.Usage, "a %s is required", fields[i])
		}
	}
	return nil
}
