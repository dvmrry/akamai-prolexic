package cli

import (
	"context"
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
