package cli

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dvmrry/akamai-prolexic/internal/mcpfront"
)

// The MCP front returns exactly the document the CLI prints as JSON: one
// contract, two fronts.
func TestMCPReturnsTheCLIDocument(t *testing.T) {
	api := ncfAPI(t)
	ncfStatusFixtures(api)
	env := ncfEnv(api.env())
	env.Home = t.TempDir()
	cli := runCLI(t, env, "status")
	if cli.code != 0 {
		t.Fatalf("cli: exit %d: %s", cli.code, cli.stderr)
	}

	rt := (&app{env: env, section: "default"}).ops()
	rt.WriteClient = nil
	srv, err := mcpfront.New(mcpfront.Options{Runtime: rt, Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "status", Arguments: map[string]any{}})
	if err != nil || res.IsError || len(res.Content) != 1 {
		t.Fatalf("mcp: %+v, %v", res, err)
	}
	if got := res.Content[0].(*mcp.TextContent).Text; got != cli.stdout {
		t.Errorf("mcp document differs from the CLI's:\nmcp: %s\ncli: %s", got, cli.stdout)
	}
}

// The SDK runs tool calls concurrently, and each builds its clients through
// the CLI's wiring: the CA bundle loads once, without a race (make race and
// CI run this under the race detector), and every call trusts it.
func TestMCPConcurrentCallsShareTheCABundle(t *testing.T) {
	env, bundle := tlsAPI(t)
	a := &app{env: env, section: "default", caBundle: bundle}
	rt := a.ops()
	rt.WriteClient = nil
	srv, err := mcpfront.New(mcpfront.Options{Runtime: rt, Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for range 8 {
		wg.Go(func() {
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "aliases_list", Arguments: map[string]any{}})
			if err != nil || res.IsError {
				errs <- fmt.Sprintf("%v %+v", err, res)
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
