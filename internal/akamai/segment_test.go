package akamai

import (
	"testing"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

func TestPathSegment(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"V1", true}, {"A-EXAMPLE", true}, {"a b", true}, {"..a", true}, {"a..", true}, {"a%2Fb", true},
		{"", false}, {".", false}, {"..", false}, {"a/b", false}, {"/", false}, {"../x", false},
	} {
		got, err := PathSegment("rule id", tc.in)
		if tc.ok {
			if err != nil || got != tc.in {
				t.Errorf("%q: got %q, %v", tc.in, got, err)
			}
			continue
		}
		if apperr.KindOf(err) != apperr.Usage {
			t.Errorf("%q: want usage error, got %v", tc.in, err)
		}
	}
	_, err := PathSegment("rule id", "..")
	if want := `rule id "..": can't be empty, ".", "..", or contain "/"`; err == nil || err.Error() != want {
		t.Errorf("message = %v, want %s", err, want)
	}
}
