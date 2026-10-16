package hygiene

import (
	"go/scanner"
	"go/token"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dvmrry/akamai-prolexic/internal/textsafe"
)

// TestTrackedFilesHaveNoInvisibleCharacters keeps out what a copy-paste
// carries in unseen: bidi overrides that make code read differently from how
// it compiles (Trojan Source), zero-width characters, tag characters and
// variation selectors that can smuggle text to a reader or an agent, a BOM,
// carriage returns. Write such a character in Go as an escape or a code
// point, never raw.
func TestTrackedFilesHaveNoInvisibleCharacters(t *testing.T) {
	for _, f := range trackedTextFiles(t) {
		if !utf8.Valid(f.body) {
			t.Errorf("%s: not valid UTF-8", f.rel)
			continue
		}
		for i, line := range strings.Split(string(f.body), "\n") {
			if r, at, ok := textsafe.Find(line); ok {
				t.Errorf("%s:%d:%d: invisible character U+%04X", f.rel, i+1, at+1, r)
			}
		}
	}
}

// TestGoIdentifiersAreASCII refuses look-alike letters in Go identifiers: a
// Cyrillic "а" makes a second name that reads the same as the first.
func TestGoIdentifiersAreASCII(t *testing.T) {
	for _, f := range trackedTextFiles(t) {
		if !strings.HasSuffix(f.rel, ".go") {
			continue
		}
		fset := token.NewFileSet()
		var s scanner.Scanner
		s.Init(fset.AddFile(f.rel, -1, len(f.body)), f.body, nil, 0)
		for {
			pos, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			if tok == token.IDENT && !isASCII(lit) {
				t.Errorf("%s: identifier %+q is not ASCII", fset.Position(pos), lit)
			}
		}
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
