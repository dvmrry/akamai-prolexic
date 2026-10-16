package ops

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ExportDoc is the result of export.
type ExportDoc struct {
	output.Header
	File          string            `json:"file"`
	Created       bool              `json:"created" doc:"The file did not exist: bootstrapped from every editable alias."`
	Written       bool              `json:"written" doc:"False when the file already held exactly the exported bytes."`
	Aliases       []ncf.ExportAlias `json:"aliases" doc:"The aliases in the written file, sorted by name, with their delta to the file's previous entries."`
	OwnSpaceAdded []string          `json:"ownSpaceAdded" doc:"Protected-destination aliases this export declared in ownSpace.aliases: a deployed rule uses them as its destination."`
}

func (*ExportDoc) SchemaID() string { return "prolexic.export.v1" }

func (d *ExportDoc) WriteText(w io.Writer) error {
	added, removed := 0, 0
	for _, al := range d.Aliases {
		for _, e := range al.Added {
			fmt.Fprintf(w, "+ %s %s\n", al.Name, e)
		}
		for _, e := range al.Removed {
			fmt.Fprintf(w, "- %s %s\n", al.Name, e)
		}
		added, removed = added+len(al.Added), removed+len(al.Removed)
	}
	verb := "unchanged"
	switch {
	case d.Created:
		verb = "created"
	case d.Written:
		verb = "written"
	}
	if _, err := fmt.Fprintf(w, "%s: %s, %d aliases, +%d -%d\n", d.File, verb, len(d.Aliases), added, removed); err != nil {
		return err
	}
	for _, name := range d.OwnSpaceAdded {
		if _, err := fmt.Fprintf(w, "own space: declared %s (a deployed rule's destination: addresses you protect)\n", name); err != nil {
			return err
		}
	}
	return nil
}

// ExportInput writes live editable aliases to the desired file.
type ExportInput struct {
	File string // the desired file's path; a missing or empty file is bootstrapped
	All  bool   // also add the editable live aliases the file doesn't name
	// Role is the role of an alias no deployed rule references: deny or
	// allow; required. Deployed rules decide the rest.
	Role ncf.Role
}

// Export reads live state (read credentials only) and writes the editable
// aliases to the desired file in canonical form: a missing or empty file is
// bootstrapped from every editable alias; an existing one is updated to the
// live entries of the aliases it names, keeping their metadata. The file is
// written only when its bytes change.
func (r *Runtime) Export(ctx context.Context, in ExportInput) (*ExportDoc, error) {
	if in.Role != ncf.RoleDeny && in.Role != ncf.RoleAllow { // ncf.Export checks too; this is before any read
		return nil, apperr.New(apperr.Usage, "the role for aliases no deployed rule references must be deny or allow, not %q", in.Role)
	}
	defer lockFile(r.abs(in.File))()
	// A missing or empty (whitespace-only) file bootstraps: an empty file is a
	// placeholder, not a damaged desired file.
	var existing *ncf.File
	if b, rerr := os.ReadFile(r.abs(in.File)); rerr != nil || len(bytes.TrimSpace(b)) > 0 {
		f, _, err := readDesired(r.file(in.File))
		if err != nil && apperr.KindOf(err) != apperr.NotFound {
			return nil, err
		}
		existing = f
	}
	store, err := r.ncfRead()
	if err != nil {
		return nil, err
	}
	res, err := ncf.Export(ctx, store, existing, ncf.ExportOptions{All: in.All, Role: in.Role})
	if err != nil {
		return nil, err
	}
	doc := &ExportDoc{File: in.File, Created: res.Created, Aliases: res.Aliases, OwnSpaceAdded: res.OwnSpaceAdded}
	canon, err := ncf.Canonical(res.File)
	if err != nil {
		return nil, err
	}
	// Skip the write when the file already holds exactly these bytes: no
	// mtime churn, and written=false says nothing was touched.
	if old, err := readIfExists(r.file(in.File)); err != nil {
		return nil, err
	} else if !bytes.Equal(old, canon) {
		if err := writeFileAtomic(r.file(in.File), canon); err != nil {
			return nil, err
		}
		doc.Written = true
	}
	return doc, nil
}
