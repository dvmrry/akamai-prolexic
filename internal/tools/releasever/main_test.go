package main

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct{ raw, tag, err string }{
		{raw: "0.1.0\n", tag: "v0.1.0"},
		{raw: "0.1.0", tag: "v0.1.0"},
		{raw: "0.2.0-rc.1\n", tag: "v0.2.0-rc.1"},
		{raw: "", err: "one version"},
		{raw: "0.1.0\n\n", err: "one version"},
		{raw: "0.1.0\r\n", err: "one version"},
		{raw: " 0.1.0\n", err: "one version"},
		{raw: "v0.1.0\n", err: "without the v"},
		{raw: "0.1\n", err: "full semantic version"},
		{raw: "0.1.0+build\n", err: "full semantic version"},
		{raw: "01.0.0\n", err: "full semantic version"},
		{raw: "latest\n", err: "full semantic version"},
	} {
		tag, err := parse(tc.raw)
		switch {
		case tc.err == "" && (err != nil || tag != tc.tag):
			t.Errorf("parse(%q) = %q, %v; want %q", tc.raw, tag, err, tc.tag)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("parse(%q) error = %v; want one containing %q", tc.raw, err, tc.err)
		}
	}
}

func TestCheck(t *testing.T) {
	tags := []string{"v0.1.0", "v0.2.0-rc.1", "not-a-version"}
	for _, tc := range []struct{ tag, err string }{
		{tag: "v0.2.0-rc.2"},
		{tag: "v0.2.0"}, // a release is above its own prereleases
		{tag: "v0.3.0"},
		{tag: "v0.1.0", err: "already tagged"},
		{tag: "v0.2.0-rc.1", err: "already tagged"},
		{tag: "v0.1.1", err: "not above the newest tag v0.2.0-rc.1"},
		{tag: "v0.2.0-beta.1", err: "not above"}, // beta sorts before rc
	} {
		err := check(tc.tag, tags)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("check(%s) = %v; want nil", tc.tag, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("check(%s) = %v; want an error containing %q", tc.tag, err, tc.err)
		}
	}
	if err := check("v0.1.0", nil); err != nil {
		t.Errorf("the first version: %v", err)
	}
}
