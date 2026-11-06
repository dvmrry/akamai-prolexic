// Package hygiene holds repository checks: tracked files must not carry
// account data. Fixtures are synthetic and use documentation ranges.
package hygiene

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// allowed are the ranges a tracked file may mention: documentation, private,
// shared, loopback, link-local, multicast, reserved and unspecified space.
// Anything else is globally routable and could be ours.
var allowed = mustPrefixes(
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20", // documentation
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", // private
	"100.64.0.0/10",                                 // CGNAT
	"127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128", // loopback, unspecified
	"169.254.0.0/16", "fe80::/10", // link-local
	"224.0.0.0/4", "ff00::/8", // multicast
	"240.0.0.0/4", "255.255.255.255/32", // reserved
	"192.0.0.0/24", "198.18.0.0/15", "64:ff9b::/96", "::ffff:0:0/96", // IETF, benchmarking, translation
)

// skip are tracked paths exempt from the scans: vendored public specs. Every
// other file is scanned as text, so a binary must be listed here: a NUL byte
// doesn't exempt a file, it is reported as an invisible character.
var skip = []string{"api/akamai-apis/"}

var (
	ipv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	ipv6 = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?|(?i)\b[0-9a-f]{1,4}::(?:[0-9a-f]{1,4}:?){0,6}(?:/\d{1,3})?`)
)

func TestTrackedFilesUseOnlyNonRoutableAddresses(t *testing.T) {
	for _, f := range trackedTextFiles(t) {
		for i, line := range strings.Split(string(f.body), "\n") {
			for _, m := range append(ipv4.FindAllString(line, -1), ipv6.FindAllString(line, -1)...) {
				if routable(m) {
					t.Errorf("%s:%d: %q is globally routable; fixtures must use documentation ranges", f.rel, i+1, m)
				}
			}
		}
	}
}

type trackedFile struct {
	rel  string
	body []byte
}

// trackedTextFiles are the files git tracks or would add, minus skip.
func trackedTextFiles(t *testing.T) []trackedFile {
	t.Helper()
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		if os.Getenv("CI") != "" { // a skipped scan must not pass a pull request
			t.Fatalf("git ls-files: %v", err)
		}
		t.Skipf("git ls-files: %v", err)
	}
	var files []trackedFile
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" || skipped(rel) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, rel))
		if errors.Is(err, os.ErrNotExist) {
			continue // deleted in the worktree
		}
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, trackedFile{rel, b})
	}
	return files
}

func routable(s string) bool {
	var addr netip.Addr
	if p, err := netip.ParsePrefix(s); err == nil {
		addr = p.Addr()
	} else if a, err := netip.ParseAddr(s); err == nil {
		addr = a
	} else {
		return false // not an address: a version string, a time, a word
	}
	for _, p := range allowed {
		if p.Contains(addr.Unmap()) || p.Contains(addr) {
			return false
		}
	}
	return true
}

// Built at run time so this file doesn't trip its own scan.
var (
	routableV4 = strings.Repeat("8.", 3) + "8"
	routableV6 = "2600" + "::/16"
)

func TestRoutable(t *testing.T) {
	for s, want := range map[string]bool{
		"192.0.2.10": false, "198.51.100.0/24": false, "2001:db8::1": false, "10.1.2.3": false,
		routableV4: true, routableV6: true, "1.2.3": false, "::": false,
	} {
		if got := routable(s); got != want {
			t.Errorf("routable(%q) = %v, want %v", s, got, want)
		}
	}
}

func skipped(rel string) bool {
	for _, p := range skip {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
