package ops

import (
	"bytes"
	"fmt"
	"io"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ValidateDoc is the result of the offline checks.
type ValidateDoc struct {
	output.Header
	File     string        `json:"file"`
	Valid    bool          `json:"valid" doc:"No error findings."`
	Findings []ncf.Finding `json:"findings"`
}

func (*ValidateDoc) SchemaID() string { return "prolexic.validate.v1" }

func (d *ValidateDoc) Outcome() error {
	if !d.Valid {
		return apperr.New(apperr.Validation, "%s has errors", d.File)
	}
	return nil
}

func (d *ValidateDoc) WriteText(w io.Writer) error {
	if err := writeFindings(w, d.Findings); err != nil {
		return err
	}
	verdict := "valid"
	if !d.Valid {
		verdict = "INVALID"
	}
	_, err := fmt.Fprintf(w, "%s: %s\n", d.File, verdict)
	return err
}

// ValidateInput names the desired file to check offline.
type ValidateInput struct {
	File string // the desired file's path
}

// Validate runs the offline checks: no credentials, no network.
func (r *Runtime) Validate(in ValidateInput) (*ValidateDoc, error) {
	f, raw, err := readDesired(r.file(in.File))
	if err != nil {
		return nil, err
	}
	doc := &ValidateDoc{File: in.File, Findings: nonNil(r.checker().Validate(f, raw))}
	doc.Valid = !ncf.HasErrors(doc.Findings)
	return doc, nil
}

// FmtDoc is the result of fmt.
type FmtDoc struct {
	output.Header
	File      string `json:"file"`
	Canonical bool   `json:"canonical" doc:"Whether the file was already canonical."`
	Written   bool   `json:"written"`

	check bool // only checked: a file that isn't canonical is the outcome, not rewritten
}

func (*FmtDoc) SchemaID() string { return "prolexic.fmt.v1" }

func (d *FmtDoc) Outcome() error {
	if d.check && !d.Canonical {
		return apperr.New(apperr.Validation, "%s is not in canonical form; run prolexic fmt", d.File)
	}
	return nil
}

func (d *FmtDoc) WriteText(w io.Writer) error {
	var err error
	switch {
	case d.Canonical:
		_, err = fmt.Fprintf(w, "%s: canonical\n", d.File)
	case d.Written:
		_, err = fmt.Fprintf(w, "%s: rewritten in canonical form\n", d.File)
	default:
		_, err = fmt.Fprintf(w, "%s: NOT canonical\n", d.File)
	}
	return err
}

// FmtInput rewrites the desired file in canonical form, or only checks it.
type FmtInput struct {
	File  string // the desired file's path
	Check bool   // write nothing; a file that isn't canonical is the outcome
}

// Fmt rewrites the desired file in canonical form, offline.
func (r *Runtime) Fmt(in FmtInput) (*FmtDoc, error) {
	defer lockFile(r.abs(in.File))()
	f, raw, err := readDesired(r.file(in.File))
	if err != nil {
		return nil, err
	}
	canon, err := ncf.Canonical(f)
	if err != nil {
		return nil, err
	}
	doc := &FmtDoc{File: in.File, Canonical: bytes.Equal(raw, canon), check: in.Check}
	if doc.Canonical || in.Check {
		return doc, nil
	}
	if err := writeFileAtomic(r.file(in.File), canon); err != nil {
		return nil, err
	}
	doc.Written = true
	return doc, nil
}

// ChangeDoc is the result of add or remove: what changed in the file, and
// the findings that decided whether it was written.
type ChangeDoc struct {
	output.Header
	File     string        `json:"file"`
	Action   string        `json:"action" enum:"add,remove"`
	Alias    string        `json:"alias"`
	Ticket   string        `json:"ticket"`
	Entries  []ncf.Entry   `json:"entries" doc:"The entries added, or removed with the metadata they had."`
	Written  bool          `json:"written" doc:"False when a finding blocked the change; the file is untouched."`
	Findings []ncf.Finding `json:"findings"`
}

func (*ChangeDoc) SchemaID() string { return "prolexic.change.v1" }

func (d *ChangeDoc) Outcome() error {
	if !d.Written {
		return apperr.New(apperr.Validation, "%s: not written", d.File)
	}
	return nil
}

func (d *ChangeDoc) WriteText(w io.Writer) error {
	sign := "+"
	if d.Action == "remove" {
		sign = "-"
	}
	for _, e := range d.Entries {
		fmt.Fprintf(w, "%s %s %s\n", sign, d.Alias, e.CIDR)
	}
	if err := writeFindings(w, d.Findings); err != nil {
		return err
	}
	verdict := "written"
	if !d.Written {
		verdict = "NOT written"
	}
	_, err := fmt.Fprintf(w, "%s: %s (ticket %s)\n", d.File, verdict, d.Ticket)
	return err
}

// AddInput adds entries, with their metadata, to one alias of the desired
// file.
type AddInput struct {
	File string // the desired file's path
	ncf.AddRequest
}

// Add adds entries to one alias and rewrites the file canonically, unless a
// finding blocks the change (ncf.Change.Blocked); then nothing is written.
func (r *Runtime) Add(in AddInput) (*ChangeDoc, error) {
	defer lockFile(r.abs(in.File))()
	f, raw, err := readDesired(r.file(in.File))
	if err != nil {
		return nil, err
	}
	ch, err := r.checker().AddEntries(f, raw, in.AddRequest)
	if err != nil {
		return nil, err
	}
	return commitChange(r.file(in.File), &ChangeDoc{File: in.File, Action: "add", Ticket: in.Ticket}, ch)
}

// RemoveInput removes entries from one alias of the desired file.
type RemoveInput struct {
	File string // the desired file's path
	ncf.RemoveRequest
}

// Remove removes entries from one alias and rewrites the file canonically,
// unless a finding blocks the change.
func (r *Runtime) Remove(in RemoveInput) (*ChangeDoc, error) {
	defer lockFile(r.abs(in.File))()
	f, raw, err := readDesired(r.file(in.File))
	if err != nil {
		return nil, err
	}
	ch, err := r.checker().RemoveEntries(f, raw, in.RemoveRequest)
	if err != nil {
		return nil, err
	}
	return commitChange(r.file(in.File), &ChangeDoc{File: in.File, Action: "remove", Ticket: in.Ticket}, ch)
}

// commitChange writes the change to path unless its findings block it.
func commitChange(path file, doc *ChangeDoc, ch *ncf.Change) (*ChangeDoc, error) {
	doc.Alias, doc.Entries, doc.Findings = ch.Alias, ch.Entries, ch.Findings
	if ch.Blocked() {
		return doc, nil // not written: Outcome reports it
	}
	canon, err := ncf.Canonical(ch.File)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, canon); err != nil {
		return nil, err
	}
	doc.Written = true
	return doc, nil
}
