// Package apperr carries the CLI's stable exit codes. Every error that reaches
// the user is an *Error, or is classified as a bug (or a cancellation) by
// CodeOf.
package apperr

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Code is a process exit code. The values are a public contract: pipelines
// branch on them.
type Code int

const (
	OK          Code = 0
	Bug         Code = 1
	Usage       Code = 2
	Credentials Code = 3
	NotFound    Code = 4 // not found, or unsupported
	Upstream    Code = 5
	Validation  Code = 6
	Drift       Code = 7 // drift, or the plan digest moved
	Conflict    Code = 8
	Cancelled   Code = 130
)

var kinds = map[Code]string{
	OK:          "ok",
	Bug:         "bug",
	Usage:       "usage",
	Credentials: "credentials",
	NotFound:    "not_found",
	Upstream:    "upstream",
	Validation:  "validation",
	Drift:       "drift",
	Conflict:    "conflict",
	Cancelled:   "cancelled",
}

// Kind is the code's stable name, as it appears in error documents.
func (c Code) Kind() string {
	if k, ok := kinds[c]; ok {
		return k
	}
	return "bug"
}

// Error is an error with an exit code. Upstream, when set, describes the
// failed API call.
type Error struct {
	Code     Code
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
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap returns an *Error with a formatted message that wraps err.
func Wrap(code Code, err error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Err: err}
}

// CodeOf classifies err: nil is OK, a cancelled context is Cancelled, an
// expired deadline is Upstream, an *Error is its own code, and anything
// else is a bug.
func CodeOf(err error) Code {
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
		return e.Code
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
