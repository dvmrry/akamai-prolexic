// Command releasever prints the version a change releases, or "none". A change
// releases exactly when it adds one notes file docs/releases/vX.Y.Z.md: the file
// name is the version and its contents are the release notes, so the version is
// reviewed with the change, and no bot opens a release pull request.
//
//	releasever BASE HEAD
//
// The version must be the next patch, minor or major after the highest vX.Y.Z
// tag. Released notes are never edited, so a change that modifies one fails;
// deleting old notes is allowed, since the published release keeps them. The
// pull request check and the release workflow both run this, so a merge
// publishes exactly what review saw.
//
// Tags are read from the local clone (git tag), so CI checks out with tags.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const none = "none"

var (
	notesFile = regexp.MustCompile(`^docs/releases/(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\.md$`)
	version   = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)$`)
)

func main() {
	out, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasever:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func run(args []string) (string, error) {
	if len(args) != 2 {
		return "", errors.New("usage: releasever BASE HEAD")
	}
	base, head := args[0], args[1]
	changes, err := git("diff", "--no-renames", "--name-status", base, head, "--", "docs/releases/")
	if err != nil {
		return "", err
	}
	tags, err := git("tag", "--list")
	if err != nil {
		return "", err
	}
	return decide(changes, strings.Fields(tags), func(path string) (string, error) {
		return git("show", head+":"+path)
	})
}

// decide says what a change releases, from its changes under docs/releases
// (git diff --name-status), the tags, and how to read a file at the change.
func decide(changes string, tags []string, read func(path string) (string, error)) (string, error) {
	var added []string
	for line := range strings.Lines(changes) {
		status, path, ok := strings.Cut(strings.TrimSpace(line), "\t")
		switch {
		case !ok:
			return "", fmt.Errorf("can't read the change %q", line)
		case status == "A":
			added = append(added, path)
		case status != "D":
			return "", fmt.Errorf("released notes are immutable; %s is %s in this change", path, status)
		}
	}
	if len(added) == 0 {
		return none, nil
	}
	if len(added) > 1 {
		return "", fmt.Errorf("a change releases one version; it adds %d notes files: %s", len(added), strings.Join(added, ", "))
	}

	path := added[0]
	m := notesFile.FindStringSubmatch(path)
	if m == nil {
		return "", fmt.Errorf("a notes file is named docs/releases/vMAJOR.MINOR.PATCH.md: %s", path)
	}
	tag := m[1]
	notes, err := read(path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(notes) == "" {
		return "", fmt.Errorf("%s is empty; its contents are the release notes", path)
	}
	if slices.Contains(tags, tag) {
		return "", fmt.Errorf("tag %s already exists", tag)
	}

	latest := "no release"
	var major, minor, patch int
	for _, t := range tags {
		ma, mi, pa, ok := parseTag(t)
		if ok && (latest == "no release" || compare(ma, mi, pa, major, minor, patch) > 0) {
			latest, major, minor, patch = t, ma, mi, pa
		}
	}
	nextPatch := fmt.Sprintf("v%d.%d.%d", major, minor, patch+1)
	nextMinor := fmt.Sprintf("v%d.%d.0", major, minor+1)
	nextMajor := fmt.Sprintf("v%d.0.0", major+1)
	if tag != nextPatch && tag != nextMinor && tag != nextMajor {
		return "", fmt.Errorf("%s does not follow %s; the next version is %s, %s or %s", tag, latest, nextPatch, nextMinor, nextMajor)
	}
	return tag, nil
}

// parseTag reads a vX.Y.Z tag; any other tag isn't a release.
func parseTag(tag string) (major, minor, patch int, ok bool) {
	m := version.FindStringSubmatch(tag)
	if m == nil {
		return 0, 0, 0, false
	}
	var parts [3]int
	for i := range parts {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return 0, 0, 0, false
		}
		parts[i] = n
	}
	return parts[0], parts[1], parts[2], true
}

func compare(aMajor, aMinor, aPatch, bMajor, bMinor, bPatch int) int {
	return slices.Compare([]int{aMajor, aMinor, aPatch}, []int{bMajor, bMinor, bPatch})
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return "", fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return string(out), nil
}
