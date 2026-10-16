package hygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/dvmrry/akamai-prolexic/"

// sdk are the packages other fronts may build on (docs/design.md, Layers).
var sdk = []string{
	"internal/akamai", "internal/edgegrid", "internal/analytics", "internal/networkhealth",
	"internal/ncf", "internal/ncf/ncfapi", "internal/ncf/ncfanalytics", "internal/ncf/ncftest", "internal/apperr", "internal/textsafe", "internal/version",
}

// frontOnly are imports the SDK must never use: the fronts, and the operations
// layer above the SDK.
var frontOnly = []string{module + "internal/cli", module + "internal/ops", module + "internal/output", module + "internal/jsonschema", "github.com/spf13/cobra"}

// TestLayers keeps dependencies pointing down: the SDK never imports a front,
// and only the CLI and its tools import Cobra or the CLI.
func TestLayers(t *testing.T) {
	imports := map[string][]string{} // package dir → imports, test files included
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join("..", "..", top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			dir := filepath.ToSlash(strings.TrimPrefix(filepath.Dir(p), filepath.Join("..", "..")+string(filepath.Separator)))
			for _, s := range f.Imports {
				path, _ := strconv.Unquote(s.Path.Value)
				imports[dir] = append(imports[dir], path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range sdk {
		if _, ok := imports[p]; !ok {
			t.Errorf("%s: listed as SDK but not found", p)
		}
	}
	for dir, deps := range imports {
		for _, dep := range deps {
			isFront := slices.ContainsFunc(frontOnly, func(f string) bool { return dep == f || strings.HasPrefix(dep, f+"/") })
			if slices.Contains(sdk, dir) && isFront {
				t.Errorf("%s (SDK) imports %s (a front)", dir, dep)
			}
			cliSide := dir == "internal/cli" || strings.HasPrefix(dir, "internal/tools/") || strings.HasPrefix(dir, "cmd/")
			if (strings.HasPrefix(dep, "github.com/spf13/cobra") || dep == module+"internal/cli") && !cliSide {
				t.Errorf("%s imports %s: only the CLI and its tools may", dir, dep)
			}
		}
	}
}

// TestSDKNamesNoFlags keeps CLI flag names out of SDK and operation messages
// (and document schemas): neither can know which front called it, so they
// word errors in domain terms.
func TestSDKNamesNoFlags(t *testing.T) {
	flag := regexp.MustCompile(`(^|[\s("'])--[a-z]`)
	for _, dir := range append(slices.Clone(sdk), "internal/ops") {
		files, _ := filepath.Glob(filepath.Join("..", "..", dir, "*.go"))
		for _, p := range files {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && flag.MatchString(lit.Value) {
					t.Errorf("%s: %s names a CLI flag", p, lit.Value)
				}
				return true
			})
		}
	}
}
