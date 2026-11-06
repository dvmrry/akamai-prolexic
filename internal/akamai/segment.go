package akamai

import (
	"strings"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// PathSegment returns v if it can be one segment of a request path, and a
// usage error otherwise. what names the value in domain words ("rule id"),
// never a CLI flag. Every SDK method that puts a caller's value into a path
// calls it; the transport's clean-path check is only the backstop.
func PathSegment(what, v string) (string, error) {
	if v == "" || v == "." || v == ".." || strings.Contains(v, "/") {
		return "", apperr.New(apperr.Usage, `%s %q: can't be empty, ".", "..", or contain "/"`, what, v)
	}
	return v, nil
}
