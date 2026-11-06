// Package apperr is the error model every layer shares: an error's kind, set
// where the failure is understood, and the upstream detail of a failed API
// call. Fronts translate kinds at the edge; the CLI maps them to exit codes
// (internal/cli/exit.go). Every error is an *Error, or is classified as a bug
// (or a cancellation) by KindOf.
package apperr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Kind is what went wrong, as a stable name. Kinds appear in error documents
// and failure lists, so the values are a public contract.
type Kind string

const (
	OK          Kind = "ok"
	Bug         Kind = "bug"
	Usage       Kind = "usage" // the input is invalid
	Credentials Kind = "credentials"
	NotFound    Kind = "not_found" // not found, or unsupported
	Upstream    Kind = "upstream"
	Validation  Kind = "validation"
	Drift       Kind = "drift" // drift, or the plan digest moved
	Conflict    Kind = "conflict"
	Cancelled   Kind = "cancelled"
)

// Error is an error with a kind. Upstream, when set, describes the failed API
// call.
type Error struct {
	Kind     Kind
	Message  string
	Upstream *UpstreamDetail
	Err      error
}

// UpstreamDetail is what the CLI reports about a failed API call. It never
// carries request headers or credentials.
type UpstreamDetail struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status,omitempty"`
	ErrorCode string `json:"errorCode,omitempty"`
	Title     string `json:"title,omitempty"`
	Detail    string `json:"detail,omitempty"`
	// IncidentID is the gateway's incident reference, for Akamai support.
	IncidentID string `json:"incidentId,omitempty"`
	// Ambiguous is set when a non-idempotent request may or may not have
	// taken effect (a transport failure or a 5xx after the request was sent).
	Ambiguous bool `json:"ambiguous,omitempty"`
}

func (e *Error) Error() string {
	switch {
	case e.Err != nil && e.Message != "":
		return e.Message + ": " + e.Err.Error()
	case e.Err != nil:
		return e.Err.Error()
	default:
		return e.Message
	}
}

func (e *Error) Unwrap() error { return e.Err }

// New returns an *Error with a formatted message.
func New(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Wrap returns an *Error with a formatted message that wraps err.
func Wrap(kind Kind, err error, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...), Err: err}
}

// KindOf classifies err: nil is OK, a cancelled context is Cancelled, an
// expired deadline is Upstream, an *Error is its own kind, and anything
// else is a bug.
func KindOf(err error) Kind {
	if err == nil {
		return OK
	}
	if errors.Is(err, context.Canceled) {
		return Cancelled
	}
	// A deadline is a request that ran out of time upstream, not a bug.
	if errors.Is(err, context.DeadlineExceeded) {
		return Upstream
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Bug
}

// UpstreamOf returns the upstream detail of the first *Error in err's chain
// that has one.
func UpstreamOf(err error) *UpstreamDetail {
	for err != nil {
		var e *Error
		if !errors.As(err, &e) {
			return nil
		}
		if e.Upstream != nil {
			return e.Upstream
		}
		err = e.Err
	}
	return nil
}

// IsNotFound reports whether err is an upstream 404. Several reads treat that
// as "nothing here" rather than a failure.
func IsNotFound(err error) bool {
	u := UpstreamOf(err)
	return u != nil && u.Status == http.StatusNotFound
}
