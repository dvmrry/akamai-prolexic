package cli

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ExportAlias is the change export made to one alias of the file.
type ExportAlias struct {
	Name    string   `json:"name"`
	ID      int64    `json:"id"`
	Added   []string `json:"added" doc:"Live entries the file did not have; all of them for a new alias."`
	Removed []string `json:"removed" doc:"Entries the file had that are no longer live."`
}

// ExportDoc is the result of export.
type ExportDoc struct {
	output.Header
	File    string        `json:"file"`
	Created bool          `json:"created" doc:"The file did not exist: bootstrapped from every editable alias."`
	Written bool          `json:"written" doc:"False when the file already held exactly the exported bytes."`
	Aliases []ExportAlias `json:"aliases" doc:"The aliases in the written file, sorted by name, with their delta to the file's previous entries."`
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
	_, err := fmt.Fprintf(w, "%s: %s, %d aliases, +%d -%d\n", d.File, verb, len(d.Aliases), added, removed)
	return err
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
	if role != ncf.RoleDeny && role != ncf.RoleAllow {
		return nil, apperr.New(apperr.Usage, "--role must be deny or allow, not %q", roleFlag)
	}

	// A missing or empty (whitespace-only) file bootstraps: an empty file is a
	// placeholder, not a damaged desired file.
	created := false
	var f *ncf.File
	var err error
	if b, rerr := os.ReadFile(file); rerr == nil && len(bytes.TrimSpace(b)) == 0 {
		created = true
	} else if f, _, err = readDesired(file); err != nil {
		if apperr.CodeOf(err) != apperr.NotFound {
			return nil, err
		}
		created = true
	}
	store, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	live, err := store.ListAliases(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]ncf.LiveAlias{}
	for _, l := range live {
		byID[l.ID] = l
	}

	// The deployed rules decide each alias's role where one references it
	// (plan rejects a file that disagrees); --role covers the rest.
	var rules map[int]ncf.ACLRule
	for _, l := range live {
		if l.Editable && len(l.ProdRules) > 0 {
			deployed, err := store.DeployedRules(ctx)
			if err != nil {
				return nil, err
			}
			rules = ncf.RulesByIndex(deployed)
			break
		}
	}
	roleOf := func(l ncf.LiveAlias, fallback ncf.Role) ncf.Role {
		if r, ok := ncf.DerivedRole(l.Name, l.ProdRules, rules); ok {
			return r
		}
		return fallback
	}

	// fetch reads one editable alias's entries, normalised and deduplicated.
	// The managed (non-editable) aliases never get here.
	fetch := func(l ncf.LiveAlias) ([]ncf.Value, error) {
		full, err := store.GetAlias(ctx, l.ID)
		if err != nil {
			return nil, err
		}
		var vals []ncf.Value
		seen := map[string]bool{}
		for _, s := range full.Entries {
			v, err := ncf.ParseLive(s)
			if err != nil {
				return nil, apperr.New(apperr.Upstream, "alias %s (%d) holds an entry export can't read: %q: %v", l.Name, l.ID, s, err)
			}
			if !seen[v.String()] {
				seen[v.String()] = true
				vals = append(vals, v)
			}
		}
		slices.SortFunc(vals, ncf.Compare)
		return vals, nil
	}
	strs := func(vs []ncf.Value) []string {
		out := make([]string, len(vs))
		for i, v := range vs {
			out[i] = v.String()
		}
		return out
	}

	var targets []ncf.LiveAlias // live aliases the file will hold, in file order then new ones
	if created {
		f = &ncf.File{Schema: ncf.DesiredSchemaID, OwnSpace: ncf.OwnSpace{Prefixes: []string{}, Aliases: []string{}}}
		for _, l := range live {
			if l.Editable {
				targets = append(targets, l)
			}
		}
		accounts := map[string]bool{}
		for _, l := range targets {
			if l.AccountID != "" {
				accounts[l.AccountID] = true
			}
		}
		if len(accounts) != 1 {
			return nil, apperr.New(apperr.Validation, "can't set accountId: the editable aliases report %d distinct account ids", len(accounts))
		}
		for id := range accounts {
			f.AccountID = id
		}
	} else {
		for _, al := range f.Aliases {
			l, ok := byID[al.ID]
			switch {
			case !ok:
				return nil, apperr.New(apperr.Validation, "alias %s: id %d is not live", al.Name, al.ID)
			case l.Name != al.Name || l.Type != al.Type:
				return nil, apperr.New(apperr.Validation, "alias %s: id %d is live as %s (%s), not %s (%s)", al.Name, al.ID, l.Name, l.Type, al.Name, al.Type)
			case !l.Editable:
				return nil, apperr.New(apperr.Validation, "alias %s (%d) is Akamai-managed; it can't be exported", al.Name, al.ID)
			}
		}
	}

	doc := &ExportDoc{File: file, Created: created, Aliases: []ExportAlias{}}
	var aliases []ncf.Alias
	inFile := map[int64]bool{}
	for _, al := range f.Aliases {
		inFile[al.ID] = true
		vals, err := fetch(byID[al.ID])
		if err != nil {
			return nil, err
		}
		meta := map[string]ncf.Entry{}
		have := map[string]string{} // normalised -> as the file has it
		for _, e := range al.Entries {
			if v, err := ncf.ParseAuthored(e.CIDR); err == nil {
				meta[v.String()] = e
				have[v.String()] = v.String()
			} else {
				have[e.CIDR] = e.CIDR
			}
		}
		ex := ExportAlias{Name: al.Name, ID: al.ID, Added: []string{}, Removed: []string{}}
		liveSet := map[string]bool{}
		var entries []ncf.Entry
		for _, v := range vals {
			s := v.String()
			liveSet[s] = true
			if e, ok := meta[s]; ok {
				e.CIDR = s
				entries = append(entries, e)
			} else {
				entries = append(entries, ncf.Entry{CIDR: s})
				ex.Added = append(ex.Added, s)
			}
		}
		for _, k := range sortedKeys(have) {
			if !liveSet[k] {
				ex.Removed = append(ex.Removed, k)
			}
		}
		al.Entries = entries
		al.Role = roleOf(byID[al.ID], al.Role)
		aliases = append(aliases, al)
		doc.Aliases = append(doc.Aliases, ex)
	}
	if created || all { // bootstrap takes every editable alias; otherwise only --all does
		for _, l := range live {
			if !l.Editable || inFile[l.ID] {
				continue
			}
			vals, err := fetch(l)
			if err != nil {
				return nil, err
			}
			al := ncf.Alias{Name: l.Name, ID: l.ID, Type: l.Type, Role: roleOf(l, role), Entries: []ncf.Entry{}}
			for _, v := range vals {
				al.Entries = append(al.Entries, ncf.Entry{CIDR: v.String()})
			}
			aliases = append(aliases, al)
			doc.Aliases = append(doc.Aliases, ExportAlias{Name: l.Name, ID: l.ID, Added: strs(vals), Removed: []string{}})
		}
	}
	slices.SortStableFunc(doc.Aliases, func(x, y ExportAlias) int { return cmp.Compare(x.Name, y.Name) })

	f.Aliases = aliases
	canon, err := ncf.Canonical(f)
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

// sortedKeys orders entry strings like the canonical file: parsable ones by
// ncf.Compare, then the rest as written.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y string) int {
		vx, ex := ncf.ParseAuthored(x)
		vy, ey := ncf.ParseAuthored(y)
		switch {
		case ex == nil && ey == nil:
			return ncf.Compare(vx, vy)
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		}
		return cmp.Compare(x, y)
	})
	return keys
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
