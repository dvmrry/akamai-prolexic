// Package mcpfront offers the operations as MCP tools to a local agent, over
// stdio: the agent's client starts `prolexic mcp` as a child process and
// talks to it on stdin and stdout. There is no listener and no network
// transport.
//
// The front reads with the read credentials only and has no apply. A change
// reaches production through version control: the agent edits the desired
// file, a person reviews the pull request and its plan, and CI applies the
// reviewed plan with the write credentials.
//
// Every tool returns the same document the CLI prints as JSON, written by
// internal/output, which escapes invisible characters: API-supplied text
// (alias names, ACL comments) reaches a model's context.
package mcpfront

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/jsonschema"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
	"github.com/dvmrry/akamai-prolexic/internal/version"
)

// Instructions is what the server tells the agent when it connects.
const Instructions = `prolexic: Akamai Prolexic and Network Cloud Firewall, read-only, plus local files: edits to the desired file (add, remove, fmt, export) and saved plans (plan with out).

Every tool returns a JSON document with a "schema" field (prolexic.<name>.v1). A result with an "outcome" note is data, not a failure: a check that isn't satisfied, or customer names whose query failed.

There is no apply. Changes to the firewall go through version control: edit the desired file with add or remove, plan it, and open a pull request. A person reviews the plan, and CI applies the reviewed plan with write credentials. Don't look for another way to write.

File paths are relative to the root directory the server was started with (its --root, or its working directory), and must stay inside it.`

// Options configure the front.
type Options struct {
	// Runtime runs the operations. Its WriteClient must be nil: this front
	// never writes to the API.
	Runtime *ops.Runtime
	// Root is the directory file paths are resolved against and confined
	// to; empty means the working directory.
	Root string
}

// maxWaitingChecks caps the routed_check calls waiting at once: each polls
// the API for up to an hour.
const maxWaitingChecks = 4

// front is one MCP session's state: the runtime and the file root.
type front struct {
	rt    *ops.Runtime
	root  string        // absolute, symbolic links resolved
	waits chan struct{} // one slot per waiting routed_check
}

// New builds the MCP server with every tool registered.
func New(o Options) (*mcp.Server, error) {
	if o.Runtime == nil {
		return nil, apperr.New(apperr.Bug, "mcpfront: no runtime")
	}
	if o.Runtime.WriteClient != nil {
		return nil, apperr.New(apperr.Bug, "mcpfront: the MCP front reads only; give it a runtime without a write client")
	}
	root := o.Root
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, apperr.Wrap(apperr.Usage, err, "working directory")
		}
		root = wd
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "root %s", o.Root)
	}
	if root, err = filepath.Abs(root); err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "root %s", o.Root)
	}
	rt := *o.Runtime // a copy: relative paths resolve in the root, whatever the caller's runtime says
	rt.Dir = root
	f := &front{rt: &rt, root: root, waits: make(chan struct{}, maxWaitingChecks)}
	s := mcp.NewServer(&mcp.Implementation{Name: "prolexic", Version: version.Current().Version}, &mcp.ServerOptions{Instructions: Instructions})
	for _, t := range tools() {
		t.register(s, f)
	}
	return s, nil
}

// RunStdio serves the MCP session on stdin and stdout until the client
// disconnects or ctx ends.
func RunStdio(ctx context.Context, o Options) error {
	s, err := New(o)
	if err != nil {
		return err
	}
	return s.Run(ctx, &mcp.StdioTransport{})
}

// registrar is a tool, whatever its argument type.
type registrar interface {
	register(*mcp.Server, *front)
}

// tool is one MCP tool: an operation behind a typed argument struct whose
// JSON Schema is the tool's input schema.
type tool[A any] struct {
	name, title, description string
	// writes is true for a tool that writes a local file (the desired file,
	// a saved plan); every other tool only reads.
	writes bool
	// local is true for a tool that never calls the API.
	local bool
	run   func(ctx context.Context, f *front, args A) (output.Document, error)
}

func (t tool[A]) register(s *mcp.Server, f *front) {
	var zero A
	schema := jsonschema.For(zero, "prolexic.mcp."+t.name, t.title)
	delete(schema, "$id")
	schema["additionalProperties"] = false
	if _, ok := schema["properties"]; !ok {
		schema["properties"] = map[string]any{}
	}
	no, yes := false, true
	// A tool that writes overwrites a local file: destructive, though git
	// has the old one.
	destructive := t.writes
	ann := &mcp.ToolAnnotations{Title: t.title, ReadOnlyHint: !t.writes, DestructiveHint: &destructive, IdempotentHint: true, OpenWorldHint: &yes}
	if t.local {
		ann.OpenWorldHint = &no
	}
	s.AddTool(&mcp.Tool{Name: t.name, Title: t.title, Description: t.description, InputSchema: schema, Annotations: ann},
		func(ctx context.Context, req *mcp.CallToolRequest) (res *mcp.CallToolResult, _ error) {
			// The SDK doesn't recover a handler's panic: one would end the
			// session for every call. It becomes this call's error instead.
			defer func() {
				if p := recover(); p != nil {
					res = f.result(nil, apperr.New(apperr.Bug, "%s failed unexpectedly: %v", t.name, p))
				}
			}()
			var args A
			if err := decodeArgs(req.Params.Arguments, &args, schema); err != nil {
				return f.result(nil, err), nil
			}
			doc, err := t.run(ctx, f, args)
			return f.result(doc, err), nil
		})
}

// decodeArgs decodes a tool's arguments strictly: an unknown argument is an
// error, not something silently ignored, and names match the schema exactly
// at every depth (encoding/json alone would take "Prefix" for "prefix").
func decodeArgs(raw json.RawMessage, v any, schema map[string]any) error {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw = json.RawMessage("{}")
	}
	if err := exactNames(raw, schema, ""); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return apperr.Wrap(apperr.Usage, err, "arguments")
	}
	return nil
}

// result renders an operation's outcome as a tool result. A document is
// returned as the CLI prints it in JSON; an outcome (a check not satisfied,
// failed names) is a note beside it, not a tool error. An error is a tool
// error carrying the error document, after the document if there is one.
func (f *front) result(doc output.Document, err error) *mcp.CallToolResult {
	res := &mcp.CallToolResult{Content: []mcp.Content{}}
	if doc != nil {
		res.Content = append(res.Content, &mcp.TextContent{Text: f.render(doc)})
		if o, ok := doc.(interface{ Outcome() error }); ok {
			if oerr := o.Outcome(); oerr != nil {
				res.Content = append(res.Content, &mcp.TextContent{Text: "outcome: " + string(apperr.KindOf(oerr)) + ": " + output.Sanitize(oerr.Error())})
			}
		}
	}
	if err != nil {
		res.IsError = true
		// Code is the CLI's exit code; there is no process exit here, so it
		// stays 0 and kind is the contract.
		res.Content = append(res.Content, &mcp.TextContent{Text: f.render(output.NewErrorDoc(err, 0))})
	}
	return res
}

// render is doc's JSON, stamped, through output's escaping writer.
func (f *front) render(doc output.Document) string {
	now := time.Now
	if f.rt.Now != nil {
		now = f.rt.Now
	}
	output.Stamp(doc, now(), version.Current().Version)
	var buf bytes.Buffer
	if err := output.Write(&buf, output.JSON, doc); err != nil {
		return fmt.Sprintf(`{"schema":%q,"kind":"bug","message":"render: %s"}`, output.ErrorSchemaID, output.Sanitize(err.Error()))
	}
	return buf.String()
}

// path resolves a file argument against the root and keeps it there: the
// agent can't read or write a file elsewhere on disk, a symbolic link can't
// lead out of the root, and only .json files outside hidden directories are
// reachable. It returns the path relative to the root. "" stays "" (the
// operation reports the missing path). The file itself need not exist yet;
// its directory must.
func (f *front) path(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(f.root, abs)
	}
	abs = filepath.Clean(abs)
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", apperr.New(apperr.Usage, "%s: the directory doesn't exist", p)
	}
	real := filepath.Join(dir, filepath.Base(abs))
	if st, err := os.Lstat(real); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", apperr.New(apperr.Usage, "%s is a symbolic link; give the path of a real file", p)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err // its path is the resolved one, under the root
		}
		return "", apperr.New(apperr.Usage, "%s: %v", p, err)
	}
	rel, err := filepath.Rel(f.root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", apperr.New(apperr.Usage, "%s is outside the root", p)
	}
	// The tools read and write JSON: the desired file and saved plans. A
	// hidden path (.git, .github, .envrc) is never one of them, and no tool
	// should create files there.
	if filepath.Ext(rel) != ".json" {
		return "", apperr.New(apperr.Usage, "%s: the tools read and write .json files only", p)
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") {
			return "", apperr.New(apperr.Usage, "%s: hidden files and directories are off limits", p)
		}
	}
	return rel, nil // the operation opens it under the runtime's Dir (the root); documents show it as given
}

// exactNames refuses an object key the schema doesn't name exactly, at any
// depth. A value of the wrong type is left to the decoder to report.
func exactNames(raw json.RawMessage, schema map[string]any, at string) error {
	if props, ok := schema["properties"].(map[string]any); ok {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return nil
		}
		for name, v := range obj {
			p, ok := props[name].(map[string]any)
			if !ok {
				return apperr.New(apperr.Usage, "arguments: unknown field %q", at+name)
			}
			if err := exactNames(v, p, at+name+"."); err != nil {
				return err
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return nil
		}
		for i, v := range arr {
			if err := exactNames(v, items, fmt.Sprintf("%s%d.", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
