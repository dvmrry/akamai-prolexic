package jsonschema

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

type inner struct {
	N int `json:"n"`
}

type header struct {
	Schema string `json:"schema"`
}

type custom struct{}

func (custom) JSONSchema() map[string]any { return map[string]any{"type": "string", "pattern": "^x$"} }

type sample struct {
	header
	Name     string            `json:"name" doc:"The name."`
	Kind     string            `json:"kind" enum:"A,B"`
	Optional *inner            `json:"optional,omitempty"`
	List     []inner           `json:"list"`
	Tags     map[string]string `json:"tags,omitempty"`
	When     time.Time         `json:"when"`
	Custom   custom            `json:"custom"`
	Skipped  string            `json:"-"`
	private  string            //nolint:unused // proves For skips unexported fields
}

func TestFor(t *testing.T) {
	got := For(sample{}, "test.v1", "Test")
	want := map[string]any{
		"$schema":              draft,
		"$id":                  "test.v1",
		"title":                "Test",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"custom", "kind", "list", "name", "schema", "when"},
		"properties": map[string]any{
			"schema": map[string]any{"type": "string"},
			"name":   map[string]any{"type": "string", "description": "The name."},
			"kind":   map[string]any{"type": "string", "enum": []string{"A", "B"}},
			"optional": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"n"},
				"properties": map[string]any{"n": map[string]any{"type": "integer"}},
			},
			"list": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "additionalProperties": false, "required": []string{"n"},
				"properties": map[string]any{"n": map[string]any{"type": "integer"}},
			}},
			"tags":   map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"when":   map[string]any{"type": "string", "format": "date-time"},
			"custom": map[string]any{"type": "string", "pattern": "^x$"},
		},
	}
	if !reflect.DeepEqual(roundTrip(t, got), roundTrip(t, want)) {
		g, _ := Marshal(got)
		t.Errorf("schema mismatch:\n%s", g)
	}
}

func roundTrip(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDefaults(t *testing.T) {
	type args struct {
		Expect  *string `json:"expect,omitempty" default:"present"`
		Samples *int    `json:"samples,omitempty" default:"100"`
		Sum     bool    `json:"sum,omitempty" default:"false"`
		Plain   string  `json:"plain,omitempty"`
	}
	props := For(args{}, "test.v1", "Test")["properties"].(map[string]any)
	for name, want := range map[string]any{"expect": "present", "samples": float64(100), "sum": false} {
		if got := props[name].(map[string]any)["default"]; got != want {
			t.Errorf("%s: default = %#v, want %#v", name, got, want)
		}
	}
	if _, ok := props["plain"].(map[string]any)["default"]; ok {
		t.Error("plain has a default")
	}
}
