package apperr

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestCodeOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Code
	}{
		{"nil", nil, OK},
		{"plain", errors.New("boom"), Bug},
		{"typed", New(Validation, "bad"), Validation},
		{"wrapped typed", fmt.Errorf("ctx: %w", New(Drift, "moved")), Drift},
		{"cancelled", fmt.Errorf("x: %w", context.Canceled), Cancelled},
		{"cancelled beats typed", Wrap(Upstream, context.Canceled, "get"), Cancelled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CodeOf(tt.err); got != tt.want {
				t.Errorf("CodeOf = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUpstreamOfFindsNestedDetail(t *testing.T) {
	inner := &Error{Code: Upstream, Message: "get", Upstream: &UpstreamDetail{Status: 503}}
	outer := Wrap(Upstream, inner, "list aliases")
	if got := UpstreamOf(outer); got == nil || got.Status != 503 {
		t.Errorf("UpstreamOf = %+v, want status 503", got)
	}
}

func TestIsNotFound(t *testing.T) {
	notFound := Wrap(NotFound, &Error{Code: NotFound, Message: "get", Upstream: &UpstreamDetail{Status: 404}}, "read")
	if !IsNotFound(notFound) {
		t.Error("a wrapped upstream 404 is not found")
	}
	for _, err := range []error{nil, New(NotFound, "no such alias"), &Error{Code: Upstream, Upstream: &UpstreamDetail{Status: 503}}} {
		if IsNotFound(err) {
			t.Errorf("%v: only an upstream 404 counts", err)
		}
	}
}
