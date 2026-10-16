package mcpfront

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
)

// offline is a runtime with no API access: the offline tools need none, and
// any other tool fails with a credentials error.
func offline() *ops.Runtime {
	return &ops.Runtime{
		ReadClient: func() (*akamai.Client, error) {
			return nil, apperr.New(apperr.Credentials, "no credentials in this test")
		},
		Now: func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) },
		Bogons: slices.DeleteFunc(slices.Clone(ncf.Bogons), func(p netip.Prefix) bool {
			return slices.Contains(ncf.DocumentationRanges, p)
		}),
	}
}

// connect is an MCP client session with a front over in-memory transports.
func connect(t *testing.T, o Options) *mcp.ClientSession {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs
}

// call runs a tool and returns its result's text contents.
func call(t *testing.T, cs *mcp.ClientSession, name string, args any) (texts []string, isError bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, c := range res.Content {
		texts = append(texts, c.(*mcp.TextContent).Text)
	}
	return texts, res.IsError
}

// writeDesired writes a canonical desired file under dir.
func writeDesired(t *testing.T, dir string, f *ncf.File) string {
	t.Helper()
	b, err := ncf.Canonical(f)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "desired.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func desired(entries ...ncf.Entry) *ncf.File {
	return &ncf.File{Schema: ncf.DesiredSchemaID, AccountID: "A-EXAMPLE",
		OwnSpace: ncf.OwnSpace{Prefixes: []string{"203.0.113.0/24"}, Aliases: []string{}},
		Aliases:  []ncf.Alias{{Name: "block-v4", ID: 101, Type: "SOURCE", Role: ncf.RoleDeny, Entries: entries}}}
}

// The front can't write to the API: no apply tool, and no write client.
func TestReadOnly(t *testing.T) {
	rt := offline()
	rt.WriteClient = rt.ReadClient
	if _, err := New(Options{Runtime: rt, Root: t.TempDir()}); err == nil {
		t.Error("New accepted a runtime with a write client")
	}
	cs := connect(t, Options{Runtime: offline(), Root: t.TempDir()})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if strings.Contains(tl.Name, "apply") {
			t.Errorf("tool %s offers apply", tl.Name)
		}
	}
	if !strings.Contains(Instructions, "There is no apply") || !strings.Contains(Instructions, "version control") {
		t.Error("the instructions don't say apply goes through version control")
	}
}

// Every tool has a strict object schema and a description; a tool that
// writes a local file says so, and the rest are read-only.
func TestToolSchemas(t *testing.T) {
	cs := connect(t, Options{Runtime: offline(), Root: t.TempDir()})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := []string{"add", "plan", "fmt", "remove", "export"}
	for _, tl := range res.Tools {
		var s map[string]any
		b, _ := json.Marshal(tl.InputSchema)
		if err := json.Unmarshal(b, &s); err != nil || s["type"] != "object" || s["additionalProperties"] != false {
			t.Errorf("%s: schema %s", tl.Name, b)
		}
		if tl.Description == "" || tl.Annotations == nil || tl.Annotations.ReadOnlyHint == slices.Contains(writes, tl.Name) {
			t.Errorf("%s: description %q, annotations %+v", tl.Name, tl.Description, tl.Annotations)
		}
	}
}

// A default the schema shows is the one the CLI uses: the tags restate ops
// and ncf constants, which tags can't reference.
func TestSchemaDefaultsMatchTheConstants(t *testing.T) {
	cs := connect(t, Options{Runtime: offline(), Root: t.TempDir()})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defaults := map[string]any{}
	for _, tl := range res.Tools {
		b, _ := json.Marshal(tl.InputSchema)
		var s struct {
			Properties map[string]struct {
				Default any `json:"default"`
			} `json:"properties"`
		}
		_ = json.Unmarshal(b, &s)
		for name, p := range s.Properties {
			if p.Default != nil {
				defaults[tl.Name+"."+name] = p.Default
			}
		}
	}
	for key, want := range map[string]any{
		"routed_check.expect":   string(analytics.ExpectPresent),
		"routed_check.interval": ops.DefaultCheckInterval.String(),
		"plan.maxRemovals":      float64(ncf.DefaultMaxRemovals),
		"metrics.samples":       float64(ops.MetricsDefaultSamples),
		"time_series.source":    ops.TimeSeriesDefaultSource,
		"export.role":           string(ncf.RoleDeny),
	} {
		if defaults[key] != want {
			t.Errorf("%s: default %#v, want %#v", key, defaults[key], want)
		}
	}
}

func TestValidateAndAdd(t *testing.T) {
	root := t.TempDir()
	writeDesired(t, root, desired(ncf.Entry{CIDR: "192.0.2.0/25"}))
	cs := connect(t, Options{Runtime: offline(), Root: root})

	texts, isErr := call(t, cs, "validate", map[string]any{"file": "desired.json"})
	if isErr || !strings.Contains(texts[0], `"schema": "prolexic.validate.v1"`) || !strings.Contains(texts[0], `"valid": true`) {
		t.Fatalf("validate: %v %q", isErr, texts)
	}
	texts, isErr = call(t, cs, "add", map[string]any{"file": "desired.json", "alias": "block-v4", "entries": []string{"198.51.100.9"}, "ticket": "SEC-1", "reason": "scanner"})
	if isErr || !strings.Contains(texts[0], `"written": true`) {
		t.Fatalf("add: %v %q", isErr, texts)
	}
	b, _ := os.ReadFile(filepath.Join(root, "desired.json"))
	if !strings.Contains(string(b), "198.51.100.9/32") {
		t.Errorf("file = %s", b)
	}

	// A blocked change is data, not a tool error: the document and the
	// outcome beside it.
	texts, isErr = call(t, cs, "add", map[string]any{"file": "desired.json", "alias": "block-v4", "entries": []string{"198.51.100.9"}, "ticket": "SEC-1", "reason": "again"})
	if isErr || len(texts) != 2 || !strings.HasPrefix(texts[1], "outcome: validation:") || !strings.Contains(texts[0], `"written": false`) {
		t.Errorf("blocked add: %v %q", isErr, texts)
	}
	// A request the operation refuses is a tool error with the error document.
	texts, isErr = call(t, cs, "add", map[string]any{"file": "desired.json", "alias": "block-v4", "entries": []string{"198.51.100.10"}, "ticket": " ", "reason": "r"})
	if !isErr || !strings.Contains(texts[len(texts)-1], `"kind": "usage"`) {
		t.Errorf("blank ticket: %v %q", isErr, texts)
	}
}

// File arguments stay inside the root: no absolute path elsewhere, no
// climbing out, no symbolic link.
func TestPathsStayInTheRoot(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	outside := writeDesired(t, elsewhere, desired())
	if err := os.Symlink(outside, filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "dir")); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, Options{Runtime: offline(), Root: root})
	for _, p := range []string{outside, "../" + filepath.Base(elsewhere) + "/desired.json", "link.json", "dir/desired.json", "nope/desired.json"} {
		texts, isErr := call(t, cs, "validate", map[string]any{"file": p})
		if !isErr || !strings.Contains(texts[len(texts)-1], `"kind": "usage"`) {
			t.Errorf("%s: %v %q", p, isErr, texts)
		}
	}
}

// Unknown arguments are refused, not ignored.
func TestUnknownArgumentsRefused(t *testing.T) {
	cs := connect(t, Options{Runtime: offline(), Root: t.TempDir()})
	texts, isErr := call(t, cs, "validate", map[string]any{"file": "desired.json", "apply": true})
	if !isErr || !strings.Contains(texts[len(texts)-1], "unknown field") {
		t.Errorf("%v %q", isErr, texts)
	}
}

// Text from the file or the API reaches the model escaped: an invisible
// character can't hide in a result.
func TestResultsAreEscaped(t *testing.T) {
	root := t.TempDir()
	zw := string(rune(0x200b))
	writeDesired(t, root, desired(ncf.Entry{CIDR: "192.0.2.0/25", Reason: "scan" + zw + "ner"}))
	cs := connect(t, Options{Runtime: offline(), Root: root})
	texts, _ := call(t, cs, "validate", map[string]any{"file": "desired.json"})
	if strings.Contains(texts[0], zw) || !strings.Contains(texts[0], "invisible_character") {
		t.Errorf("%q", texts[0])
	}
}

// The tools are exactly these: no apply, nothing missing.
func TestToolNames(t *testing.T) {
	cs := connect(t, Options{Runtime: offline(), Root: t.TempDir()})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
	}
	slices.Sort(got)
	want := []string{
		"acl_deployment", "acl_show", "acl_test", "acl_versions", "add", "alias_show", "alias_versions", "aliases_list",
		"attack_show", "attacks_list", "customers", "events", "export", "fmt", "managed_acl", "managed_rule_hits",
		"metrics", "plan", "protected", "remove", "routed_check", "routed_health", "routed_routes", "routed_sessions",
		"rule_hit_show", "rule_hits_list", "scrub_centers", "status", "target_show", "targets_list", "time_series",
		"validate", "verify",
	}
	if !slices.Equal(got, want) {
		t.Errorf("tools\n got %v\nwant %v", got, want)
	}
}

// Every tool that calls the API maps valid minimal arguments, passes the
// operation's checks and reaches the read client, which here has no
// credentials.
func TestEveryAPIToolReachesTheAPI(t *testing.T) {
	root := t.TempDir()
	writeDesired(t, root, desired(ncf.Entry{CIDR: "192.0.2.0/25"}))
	if err := os.WriteFile(filepath.Join(root, "plan.json"), []byte(`{"schema":"prolexic.plan.v1","digest":"d","fileDigest":"f","settings":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, Options{Runtime: offline(), Root: root})
	packet := map[string]any{"protocol": "tcp", "srcIp": "198.51.100.7", "dstIp": "203.0.113.5", "srcPort": 1234, "dstPort": 443}
	cases := map[string]map[string]any{
		"status":            {},
		"routed_check":      {"prefix": "198.51.100.0/24"},
		"attacks_list":      {},
		"plan":              {"file": "desired.json"},
		"aliases_list":      {},
		"alias_show":        {"name": "example-a"},
		"alias_versions":    {"name": "example-a"},
		"acl_versions":      {},
		"acl_show":          {},
		"acl_deployment":    {},
		"acl_test":          {"packets": []any{packet}},
		"managed_acl":       {"policyDomain": "example-a"},
		"managed_rule_hits": {"policyDomain": "example-a", "rule": "r-1", "since": "1h"},
		"rule_hits_list":    {},
		"rule_hit_show":     {"rule": "r-1", "since": "1h"},
		"attack_show":       {"customer": "example-a", "id": 1},
		"events":            {"customers": []string{"example-a"}, "criticalOnly": true, "since": "1h"},
		"metrics":           {"customers": []string{"example-a"}, "types": []string{"fbm:bandwidth:tcp"}, "subnet": "203.0.113.0/24"},
		"time_series":       {"destinations": []string{"203.0.113.5"}},
		"protected":         {"customers": []string{"example-a"}},
		"customers":         {},
		"scrub_centers":     {},
		"routed_sessions":   {"customers": []string{"example-a"}},
		"routed_routes":     {"customers": []string{"example-a"}, "prefix": "198.51.100.0/24"},
		"routed_health":     {"customers": []string{"example-a"}},
		"targets_list":      {},
		"target_show":       {"id": "example-a"},
		"export":            {"file": "exported.json"},
		"verify":            {"plan": "plan.json"},
	}
	for name, args := range cases {
		texts, isErr := call(t, cs, name, args)
		if !isErr || !strings.Contains(texts[len(texts)-1], `"kind": "credentials"`) {
			t.Errorf("%s: %v %q", name, isErr, texts)
		}
	}
}

// The local tools that edit the desired file work under the root.
func TestFmtAndRemove(t *testing.T) {
	root := t.TempDir()
	p := writeDesired(t, root, desired(ncf.Entry{CIDR: "192.0.2.0/25"}, ncf.Entry{CIDR: "198.51.100.0/24"}))
	cs := connect(t, Options{Runtime: offline(), Root: root})

	texts, isErr := call(t, cs, "fmt", map[string]any{"file": "desired.json", "check": true})
	if isErr || !strings.Contains(texts[0], `"schema": "prolexic.fmt.v1"`) {
		t.Fatalf("fmt check: %v %q", isErr, texts)
	}
	texts, isErr = call(t, cs, "remove", map[string]any{"file": "desired.json", "alias": "block-v4", "entries": []string{"198.51.100.0/24"}, "ticket": "SEC-1"})
	if isErr || !strings.Contains(texts[0], `"written": true`) {
		t.Fatalf("remove: %v %q", isErr, texts)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "198.51.100.0/24") || !strings.Contains(string(b), "192.0.2.0/25") {
		t.Errorf("file = %s", b)
	}
	texts, isErr = call(t, cs, "remove", map[string]any{"file": "desired.json", "alias": "block-v4", "entries": []string{"192.0.2.0/25"}, "ticket": " "})
	if !isErr || !strings.Contains(texts[len(texts)-1], `"kind": "usage"`) {
		t.Errorf("blank ticket: %v %q", isErr, texts)
	}
	texts, isErr = call(t, cs, "fmt", map[string]any{"file": "desired.json"})
	if isErr || !strings.Contains(texts[0], `"schema": "prolexic.fmt.v1"`) {
		t.Errorf("fmt: %v %q", isErr, texts)
	}
}

// An argument the operation refuses is refused before any client is built:
// without credentials the agent still learns what's wrong with its call.
func TestArgumentChecksComeFirst(t *testing.T) {
	root := t.TempDir()
	writeDesired(t, root, desired(ncf.Entry{CIDR: "192.0.2.0/25"}))
	cs := connect(t, Options{Runtime: offline(), Root: root})
	for key, args := range map[string]map[string]any{
		"alias_show":     {},
		"alias_versions": {"name": "block-v4", "id": 101},
		"export":         {"file": "desired.json", "role": ""},
		"plan":           {"file": "desired.json", "maxRemovals": -5},
		"plan, loosened": {"file": "desired.json", "maxRemovals": -1},
		"plan, raised":   {"file": "desired.json", "maxRemovals": 11},
	} {
		name, _, _ := strings.Cut(key, ",")
		texts, isErr := call(t, cs, name, args)
		if !isErr || !strings.Contains(texts[len(texts)-1], `"kind": "usage"`) {
			t.Errorf("%s %v: %v %q", key, args, isErr, texts)
		}
	}
}

// Documents show file paths as the agent gave them, relative to the root:
// no local directory reaches the model, or a saved plan.
func TestDocumentsShowRelativePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDesired(t, filepath.Join(root, "sub"), desired(ncf.Entry{CIDR: "192.0.2.0/25"}))
	cs := connect(t, Options{Runtime: offline(), Root: root})
	texts, isErr := call(t, cs, "validate", map[string]any{"file": "sub/desired.json"})
	real, _ := filepath.EvalSymlinks(root)
	if isErr || !strings.Contains(texts[0], `"file": "sub/desired.json"`) || strings.Contains(texts[0], root) || strings.Contains(texts[0], real) {
		t.Errorf("%v %q", isErr, texts)
	}
}
