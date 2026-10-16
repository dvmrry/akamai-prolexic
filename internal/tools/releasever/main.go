// Command releasever checks the version VERSION declares and tells the
// release workflow what to tag. Every pull request to main raises VERSION,
// and merging it tags v<VERSION> and publishes the release: the version is
// reviewed with the change, and no bot opens a release pull request.
//
//	releasever check    VERSION is new and above every tag; prints the tag
//	releasever release  the release workflow's outputs (tag, prerelease):
//	                    tag is empty when VERSION is already tagged
//
// Tags are read from the local clone (git tag), so CI checks out with tags.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/mod/semver"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "releasever:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "check" && args[0] != "release") {
		return fmt.Errorf("usage: releasever check|release")
	}
	raw, err := os.ReadFile("VERSION")
	if err != nil {
		return err
	}
	tag, err := parse(string(raw))
	if err != nil {
		return err
	}
	out, err := exec.Command("git", "tag", "--list").Output()
	if err != nil {
		return fmt.Errorf("git tag: %w", err)
	}
	tags := strings.Fields(string(out))

	if args[0] == "check" {
		if err := check(tag, tags); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, tag)
		return err
	}

	// release: an already tagged VERSION releases nothing (a merge that
	// didn't raise it, such as a Dependabot update).
	outputs := stdout
	if path := os.Getenv("GITHUB_OUTPUT"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		outputs = f
	}
	if slices.Contains(tags, tag) {
		fmt.Fprintf(stdout, "::notice::%s is already tagged: nothing to release\n", tag)
		_, err := fmt.Fprintln(outputs, "tag=")
		return err
	}
	if err := check(tag, tags); err != nil {
		return err
	}
	_, err = fmt.Fprintf(outputs, "tag=%s\nprerelease=%t\n", tag, semver.Prerelease(tag) != "")
	return err
}

// parse reads VERSION: one semantic version without the v (0.1.0 or
// 0.1.0-rc.1), and returns its tag.
func parse(raw string) (string, error) {
	s := strings.TrimSuffix(raw, "\n")
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("VERSION must hold one version on one line, like 0.1.0")
	}
	if strings.HasPrefix(s, "v") {
		return "", fmt.Errorf("VERSION is written without the v: %s", strings.TrimPrefix(s, "v"))
	}
	tag := "v" + s
	// Canonical also rejects shorthand (0.1) and build metadata (0.1.0+x).
	if !semver.IsValid(tag) || semver.Canonical(tag) != tag {
		return "", fmt.Errorf("VERSION %q is not a full semantic version (X.Y.Z or X.Y.Z-rc.N)", s)
	}
	return tag, nil
}

// check refuses a tag that exists or isn't above every version tag.
func check(tag string, tags []string) error {
	if slices.Contains(tags, tag) {
		return fmt.Errorf("%s is already tagged: raise VERSION in this pull request", tag)
	}
	newest := ""
	for _, t := range tags {
		if semver.IsValid(t) && (newest == "" || semver.Compare(t, newest) > 0) {
			newest = t
		}
	}
	if newest != "" && semver.Compare(tag, newest) <= 0 {
		return fmt.Errorf("VERSION %s is not above the newest tag %s", strings.TrimPrefix(tag, "v"), newest)
	}
	return nil
}
