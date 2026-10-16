package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
	"github.com/dvmrry/akamai-prolexic/internal/version"
)

// file is a path as an operation opens it and as its messages show it: the
// caller's spelling, so neither a document nor an error names the local
// directory a front resolved it in (Runtime.Dir).
type file struct{ open, show string }

// file is the input path given, opened under Dir.
func (r *Runtime) file(given string) file { return file{open: r.abs(given), show: given} }

// readDesired reads and decodes the desired file.
func readDesired(p file) (*ncf.File, []byte, error) {
	if p.open == "" {
		return nil, nil, apperr.New(apperr.Usage, "the desired file's path is required")
	}
	fh, err := os.Open(p.open)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, apperr.New(apperr.NotFound, "no desired file %s", p.show)
	}
	if err != nil {
		return nil, nil, apperr.New(apperr.Usage, "open %s: %v", p.show, fsErr(err))
	}
	defer fh.Close()
	return ncf.Decode(fh)
}

// writeFileAtomic replaces the file with b via a temporary file in the same
// directory, keeping the file's mode.
func writeFileAtomic(p file, b []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(p.open); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.open), "."+filepath.Base(p.open)+".*")
	if err != nil {
		return apperr.New(apperr.Usage, "write %s: %v", p.show, fsErr(err))
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return apperr.New(apperr.Usage, "write %s: %v", p.show, fsErr(err))
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return apperr.New(apperr.Usage, "write %s: %v", p.show, fsErr(err))
	}
	if err := tmp.Close(); err != nil {
		return apperr.New(apperr.Usage, "write %s: %v", p.show, fsErr(err))
	}
	if err := os.Rename(tmp.Name(), p.open); err != nil {
		return apperr.New(apperr.Usage, "write %s: %v", p.show, fsErr(err))
	}
	return nil
}

// readIfExists returns the file's bytes, or nil if it doesn't exist.
func readIfExists(p file) ([]byte, error) {
	b, err := os.ReadFile(p.open)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.New(apperr.Usage, "read %s: %v", p.show, fsErr(err))
	}
	return b, nil
}

// fsErr drops the path an *os.PathError or *os.LinkError carries (for an
// atomic write, a temporary file's name) and keeps the cause.
func fsErr(err error) error {
	var pe *os.PathError
	var le *os.LinkError
	switch {
	case errors.As(err, &pe):
		return pe.Err
	case errors.As(err, &le):
		return le.Err
	}
	return err
}

// saveDocument writes doc's JSON to path, atomically, stamped as if it were
// printed. A front can show the document in another format from the same
// run, and the two can't disagree.
func (r *Runtime) saveDocument(p file, doc output.Document) error {
	output.Stamp(doc, r.now(), version.Current().Version)
	var buf bytes.Buffer
	if err := output.Write(&buf, output.JSON, doc); err != nil {
		return err
	}
	if err := writeFileAtomic(p, buf.Bytes()); err != nil {
		return apperr.Wrap(apperr.Usage, err, "save %s", p.show)
	}
	return nil
}

// checkOutPath refuses a path for a saved plan that would destroy
// something: the desired file itself, a symbolic link (the write would
// replace the link), or a directory.
func checkOutPath(outFile, desired file) error {
	out := outFile.show
	st, err := os.Lstat(outFile.open)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return apperr.New(apperr.Usage, "the plan's output path %s: %v", out, fsErr(err))
	}
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return apperr.New(apperr.Usage, "the plan's output path %s is a symbolic link; give the path of a real file", out)
	case st.IsDir():
		return apperr.New(apperr.Usage, "the plan's output path %s is a directory; give a file path", out)
	}
	if ds, err := os.Stat(desired.open); err == nil && os.SameFile(st, ds) {
		return apperr.New(apperr.Usage, "the plan's output path %s is the desired file; save the plan elsewhere", out)
	}
	// An existing file may only be a saved plan, replaced by a fresh one:
	// anything else (a CI config, a reviewed file) is not this tool's to
	// overwrite.
	b, err := os.ReadFile(outFile.open)
	if err != nil {
		return apperr.New(apperr.Usage, "the plan's output path %s: %v", out, fsErr(err))
	}
	var doc struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(b, &doc) != nil || doc.Schema != (&PlanDoc{}).SchemaID() {
		return apperr.New(apperr.Usage, "the plan's output path %s exists and isn't a saved plan; give a new path", out)
	}
	return nil
}

func writeFindings(w io.Writer, fs []ncf.Finding) error {
	for _, f := range fs {
		where := strings.TrimSpace(f.Alias + " " + f.Entry)
		if where != "" {
			where = " [" + where + "]"
		}
		if _, err := fmt.Fprintf(w, "%s %s%s: %s\n", f.Severity, f.Code, where, f.Message); err != nil {
			return err
		}
	}
	return nil
}

// fileMu serialises every read, change and write of a file within this
// process: concurrent calls (the MCP front runs tool calls in parallel)
// would otherwise each read the old file, and the last write would drop the
// other's change. One lock for all files: a lock per path would let two
// spellings of one file (Desired.json on a case-insensitive disk) race, and
// these operations are quick.
var fileMu sync.Mutex

// lockFiles takes the file lock and returns the unlock.
func lockFiles() (unlock func()) {
	fileMu.Lock()
	return fileMu.Unlock
}
