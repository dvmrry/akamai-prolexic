# prolexic

A Go CLI for Akamai Prolexic over the Akamai APIs (EdgeGrid auth). Dave owns the design; it is just beginning.

## Commands

- `make check`: gofmt, `go vet`, `go test`, gitleaks. Run before every commit.
- `make build`: `bin/prolexic`, with the version injected via ldflags.
- Hooks: `prek install --hook-type pre-commit --hook-type pre-push` once per clone (gitleaks, gofmt and vet on commit; tests on push).
- Toolchain: `direnv allow` loads the flake's devShell (go, gopls, gofumpt, golangci-lint, gitleaks, prek).

## Rules

- **Credentials:** EdgeGrid credentials live in `~/.edgerc`, never in the repo, tests or fixtures. Use synthetic `akab-` values with low entropy in tests (e.g. `akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx`); `.gitleaks.toml` flags realistic ones.
- **Captured API responses** go in `/scratch/` (gitignored) until they're scrubbed into test fixtures.
- **Languages:** Go only; tooling and scripts in Go or bash, never Python.
- **Commits:** no `Co-Authored-By` lines. Short, conventional-ish messages (`feat:`, `fix:`, `docs:`).
