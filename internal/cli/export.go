package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

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

func newExportCmd(a *app) *cobra.Command {
	var file, role string
	var all bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "write live editable aliases to the desired file (bootstrap, or adopt drift)",
		Long:  "Reads live state (read credentials only) and writes the editable aliases to the desired file in canonical form. A missing or empty file is bootstrapped from every editable alias; an existing file is updated to the live entries of the aliases it names, keeping their metadata.",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return export(ctx, a, file, all, role)
		}),
	}
	fileFlag(cmd, &file)
	cmd.Flags().BoolVar(&all, "all", false, "also add editable live aliases the file doesn't name")
	cmd.Flags().StringVar(&role, "role", string(ncf.RoleDeny), "role for aliases no deployed rule references (deployed rules decide the rest): deny or allow")
	return cmd
}

func export(ctx context.Context, a *app, file string, all bool, roleFlag string) (output.Document, error) {
	role := ncf.Role(roleFlag)
	if role != ncf.RoleDeny && role != ncf.RoleAllow { // the fallback for aliases no rule uses
		return nil, apperr.New(apperr.Usage, "--role must be deny or allow, not %q", roleFlag)
	}

	// A missing or empty (whitespace-only) file bootstraps: an empty file is a
	// placeholder, not a damaged desired file.
	var existing *ncf.File
	if b, rerr := os.ReadFile(file); rerr != nil || len(bytes.TrimSpace(b)) > 0 {
		f, _, err := readDesired(file)
		if err != nil && apperr.KindOf(err) != apperr.NotFound {
			return nil, err
		}
		existing = f
	}
	store, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	res, err := ncf.Export(ctx, store, existing, ncf.ExportOptions{All: all, Role: role})
	if err != nil {
		return nil, err
	}
	doc := &ExportDoc{File: file, Created: res.Created, Aliases: res.Aliases, OwnSpaceAdded: res.OwnSpaceAdded}
	canon, err := ncf.Canonical(res.File)
	if err != nil {
		return nil, err
	}
	// Skip the write when the file already holds exactly these bytes: no
	// mtime churn, and written=false says nothing was touched.
	if old, err := readIfExists(file); err != nil {
		return nil, err
	} else if !bytes.Equal(old, canon) {
		if err := writeFileAtomic(file, canon); err != nil {
			return nil, err
		}
		doc.Written = true
	}
	return doc, nil
}

// readIfExists returns the file's bytes, or nil if it doesn't exist.
func readIfExists(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "read %s", path)
	}
	return b, nil
}
