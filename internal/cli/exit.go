package cli

import (
	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// exitCodes maps each error kind to the process exit code. The numbers are a
// public contract (pipelines branch on them) and appear nowhere else.
var exitCodes = map[apperr.Kind]int{
	apperr.OK:          0,
	apperr.Bug:         1,
	apperr.Usage:       2,
	apperr.Credentials: 3,
	apperr.NotFound:    4,
	apperr.Upstream:    5,
	apperr.Validation:  6,
	apperr.Drift:       7,
	apperr.Conflict:    8,
	apperr.Cancelled:   130,
}

// exitCode is k's exit code; an unknown kind is a bug.
func exitCode(k apperr.Kind) int {
	if c, ok := exitCodes[k]; ok {
		return c
	}
	return exitCodes[apperr.Bug]
}

// outcomer is a document whose content can call for a non-zero exit: a check
// not satisfied, names that failed, findings with errors. The outcome is
// derived from the document's own fields, so another front can read the same
// result as data. The CLI turns it into the exit code (and the error on
// stderr) only when the command itself returned no error.
type outcomer interface {
	Outcome() error
}

// failuresOutcome is the outcome of a document listing failed customer names.
func failuresOutcome(failures []analytics.Failure, customers []string) error {
	return analytics.FailuresError(failures, len(customers))
}
