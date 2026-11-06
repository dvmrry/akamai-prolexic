package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecide(t *testing.T) {
	notes := func(string) (string, error) { return "# notes\n", nil }
	first, later := []string(nil), []string{"v0.1.0", "v0.2.3", "v0.10.0", "not-a-version", "v0.3.0-rc.1"}
	for _, tc := range []struct {
		name, changes string
		tags          []string
		want, err     string
	}{
		{name: "no notes", changes: "", tags: later, want: "none"},
		{name: "old notes deleted", changes: "D\tdocs/releases/v0.1.0.md\n", tags: later, want: "none"},
		{name: "the first release", changes: "A\tdocs/releases/v0.1.0.md\n", tags: first, want: "v0.1.0"},
		{name: "next patch", changes: "A\tdocs/releases/v0.10.1.md\n", tags: later, want: "v0.10.1"},
		{name: "next minor", changes: "A\tdocs/releases/v0.11.0.md\n", tags: later, want: "v0.11.0"},
		{name: "next major", changes: "A\tdocs/releases/v1.0.0.md\n", tags: later, want: "v1.0.0"},
		{name: "old notes deleted, new added", changes: "D\tdocs/releases/v0.1.0.md\nA\tdocs/releases/v0.10.1.md\n", tags: later, want: "v0.10.1"},

		{name: "numbers compare as numbers", changes: "A\tdocs/releases/v0.3.0.md\n", tags: later, err: "does not follow v0.10.0"},
		{name: "a skipped version", changes: "A\tdocs/releases/v0.12.0.md\n", tags: later, err: "the next version is v0.10.1, v0.11.0 or v1.0.0"},
		{name: "the first release skips", changes: "A\tdocs/releases/v0.2.0.md\n", tags: first, err: "does not follow no release"},
		{name: "already tagged", changes: "A\tdocs/releases/v0.10.0.md\n", tags: later, err: "already exists"},
		{name: "two notes", changes: "A\tdocs/releases/v0.10.1.md\nA\tdocs/releases/v0.11.0.md\n", tags: later, err: "adds 2 notes files"},
		{name: "edited notes", changes: "M\tdocs/releases/v0.1.0.md\n", tags: later, err: "immutable"},
		{name: "edited notes beside new ones", changes: "A\tdocs/releases/v0.10.1.md\nM\tdocs/releases/v0.1.0.md\n", tags: later, err: "immutable"},
		{name: "a prerelease", changes: "A\tdocs/releases/v0.11.0-rc.1.md\n", tags: later, err: "is named"},
		{name: "no v", changes: "A\tdocs/releases/0.11.0.md\n", tags: later, err: "is named"},
		{name: "a leading zero", changes: "A\tdocs/releases/v0.011.0.md\n", tags: later, err: "is named"},
		{name: "another file", changes: "A\tdocs/releases/README.md\n", tags: later, err: "is named"},
		{name: "a subdirectory", changes: "A\tdocs/releases/old/v0.11.0.md\n", tags: later, err: "is named"},
		{name: "an unreadable change", changes: "A docs/releases/v0.11.0.md\n", tags: later, err: "can't read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decide(tc.changes, tc.tags, notes)
			switch {
			case tc.err == "" && (err != nil || got != tc.want):
				t.Errorf("decide = %q, %v; want %q", got, err, tc.want)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Errorf("decide = %q, %v; want an error containing %q", got, err, tc.err)
			}
		})
	}
}

func TestDecideNeedsNotes(t *testing.T) {
	changes := "A\tdocs/releases/v0.1.0.md\n"
	if _, err := decide(changes, nil, func(string) (string, error) { return " \n\t\n", nil }); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("blank notes: %v", err)
	}
	failed := errors.New("no such file")
	if _, err := decide(changes, nil, func(string) (string, error) { return "", failed }); !errors.Is(err, failed) {
		t.Errorf("an unreadable file: %v", err)
	}
}

// The real thing: what git reports for each kind of change.
func TestRunAgainstARepository(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	sh := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func() string {
		t.Helper()
		sh("add", "-A")
		sh("commit", "-q", "--allow-empty", "-m", "c")
		return sh("rev-parse", "HEAD")
	}

	sh("init", "-q")
	write("code.go", "package x\n")
	start := commit()

	write("code.go", "package x // changed\n")
	code := commit()
	if got, err := run([]string{start, code}); err != nil || got != "none" {
		t.Errorf("a change without notes: %q, %v", got, err)
	}

	write("docs/releases/v0.1.0.md", "# v0.1.0\n")
	first := commit()
	if got, err := run([]string{code, first}); err != nil || got != "v0.1.0" {
		t.Errorf("the first notes: %q, %v", got, err)
	}
	sh("tag", "v0.1.0")
	if _, err := run([]string{code, first}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("after the tag: %v", err)
	}

	write("docs/releases/v0.1.0.md", "# v0.1.0, edited\n")
	edited := commit()
	if _, err := run([]string{first, edited}); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("edited notes: %v", err)
	}

	if err := os.Rename("docs/releases/v0.1.0.md", "docs/releases/v0.1.1.md"); err != nil {
		t.Fatal(err)
	}
	renamed := commit()
	if got, err := run([]string{edited, renamed}); err != nil || got != "v0.1.1" {
		t.Errorf("a rename counts as a delete and an add: %q, %v", got, err)
	}

	if _, err := run([]string{start, "no-such-commit"}); err == nil || !strings.Contains(err.Error(), "git diff") {
		t.Errorf("an unknown commit: %v", err)
	}
	if _, err := run([]string{start}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("one argument: %v", err)
	}
}
