# akamai-prolexic

`prolexic` is a Go CLI for Akamai Prolexic over the Akamai APIs (EdgeGrid auth). It does two things:

- It manages Network Cloud Firewall alias entries as reviewed desired state.
- It gives read-only visibility across the Prolexic APIs.

Dave owns the design. `docs/design.md` explains the model and the decisions behind it; read it before changing behaviour.

This file is for every coding agent (Claude Code reads it through `CLAUDE.md`).

## Commands

- `make check`: gofmt, `go vet`, `go test`, gitleaks. Run it before every commit.
- `make fuzz`: fuzzes the entry parser, the desired file, the entry-set hash and the plan diff for `FUZZTIME` each (default 30s). `make check` replays only their seeds; run this after touching parsing or the diff.
- `make race`, `make cross` (every release platform, without cgo), `make vuln` (govulncheck; needs the network) and `make actionlint`: CI runs these after `make check` (`.github/workflows/check.yml`), on every pull request, on pushes to main and weekly.
- `make schemas`: regenerates `schemas/` after a document type changes. `TestSchemas` fails if a type and its schema drift.
- `make docs`: regenerates `docs/cli/` (the Markdown CLI reference) from the Cobra tree after a command or flag changes. `TestDocsCurrent` fails when it is stale.
- `make build`: builds `bin/prolexic`, with the version injected through ldflags.
- `make install`: the same, into `~/go/bin`. Dave's shell abbreviates it as `plx` (dotfiles).
- Hooks: run `prek install --hook-type pre-commit --hook-type pre-push` once per clone. That gives gitleaks, gofmt and vet on commit, and tests on push. A local guard may also chain onto these hooks. Never bypass hooks (`--no-verify`, `commit -n`, `core.hooksPath`).
- Toolchain: `direnv allow` loads the flake's devShell (go, gopls, gofumpt, golangci-lint, gitleaks, prek).

## Rules

- **Credentials:** EdgeGrid credentials live in `~/.edgerc` or the environment, never in the repo, tests or fixtures. Use synthetic low-entropy `akab-` values in tests (e.g. `akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx`); `.gitleaks.toml` flags realistic ones.
- **No account data in the repo.**
  - Fixtures are synthetic: documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), documentation ASNs (64496–64511), and names like `example-a` or `A-EXAMPLE`.
  - `internal/hygiene` fails on globally routable addresses in tracked files.
- **No invisible characters.** `internal/hygiene` fails on bidi overrides, zero-width and tag characters, variation selectors, a BOM or a CR in any tracked file, and on a non-ASCII Go identifier (a look-alike letter). In Go, write such a character as an escape or a code point, never raw. Retype pasted text rather than trust it.
- **Login-only API specs** (NCF v2) go in `spec/`, which is gitignored except its README. Never commit them, and never paste their text into tracked files, including code comments, docs and fixtures. Specs from github.com/akamai/akamai-apis (Apache-2.0) are vendored under `api/akamai-apis/` with their licence.
- **Captured API responses** go in `/scratch/` (gitignored) until they're scrubbed into fixtures.
- **The live API wins over the spec.** Decode responses leniently. `docs/design.md` lists the known differences.
- **Languages:** Go only. Tooling and scripts are in Go or bash, never Python.
- **Commits:** short conventional messages (`feat:`, `fix:`, `docs:`). No attribution of any kind: no `Co-Authored-By`, no other trailer, no agent as committer.
- **No compatibility shims.** Nothing consumes the file formats or output yet, so change them and their tests directly. That changes at the first tag (`v0.1.0`).

## Layout

| package | owns |
| --- | --- |
| `internal/apperr` | the shared error model: error kinds and upstream detail (the CLI maps kinds to exit codes in `internal/cli/exit.go`) |
| `internal/textsafe` | which characters count as invisible (controls, bidi and other format characters, fillers, variation selectors): output escapes them, the desired file and the repo refuse them |
| `internal/output` | the document contract: one Document per command, JSON by default (text on request), `schema` field |
| `internal/jsonschema` | schemas derived from Go types |
| `internal/edgegrid` | credentials and request signing |
| `internal/akamai` | the HTTP transport: retries for reads only, ambiguity marking for writes, error classification |
| `internal/analytics` | Prolexic Analytics client; `ForCustomers` runs a query once per customer name (commands use it, not `FanOut` directly) |
| `internal/networkhealth` | Network Health client |
| `internal/ncf` | the desired-state core: entries, desired file, checks, role derivation, plan, apply, the `Store` port |
| `internal/ncf/ncfapi` | `Store` and reads over NCF v2 |
| `internal/ncf/ncfanalytics` | `LiveOwnSpace` over Prolexic Analytics: protected prefixes and own AS numbers for the own-space checks |
| `internal/ncf/ncftest` | in-memory versioned `Store` with fault injection |
| `internal/cli` | commands and wiring; one file per command family |

The packages form three layers (SDK, operations, fronts); `docs/design.md` (Layers) has the rules for errors and input validation. Dependencies point down only: SDK packages never import `cli`, `output`, `jsonschema` or Cobra, and `internal/hygiene` tests it. Reusable logic goes in the SDK packages, not in `internal/cli`.

New read commands follow `internal/cli/routed.go` and `internal/cli/status.go`: a document embeds `output.Header`, has a constant `SchemaID()` (`prolexic.<name>.v1`), is registered in `documents()`, and renders sorted, stable output.

## Write-path invariants

`apply` is the only command that writes. Every change to `internal/ncf` must keep these invariants, and each one has tests:

1. **Apply writes only the reviewed plan.** If the fresh plan has changes, its digest must equal `--expect-digest`. With no changes, apply writes nothing and only waits for production.
2. **A version-creating request is never re-sent.** An ambiguous create is resolved from the version list, matched on this apply's comment and source version.
3. **Activation is all or nothing.** Nothing stays activated unless every changed alias verified and activated. Failures roll back what this apply made live, but never another writer's activation. The token is re-read right before each activation.
4. **A retry re-uses its own earlier inactive version** (same digest comment and source version, entries re-verified) instead of creating another.
5. **Own space is never blocked.**
   - A deny-side source entry must not cover own space: static prefixes, own-space DIPA aliases, Analytics protected prefixes, and our own ASNs.
   - The side comes from the deployed ACL rules. Only a verified derivation can relax the checks; an unrecognised form or action is checked as deny.
   - A plan needs a live own-space source (`LiveOwnSpace`, from `ncfanalytics`) or an explicit `SkipLiveOwnSpace`, which it reports. No front can leave it out by accident.
6. **The production wait is accurate.** Every targeted alias must reach production with a healthy, settled deployment. Otherwise apply exits 5 with a message that says what is actually lagging.

## Working practice

- Keep the core in `internal/ncf`. Commands wire it up; they don't reimplement checks.
- Pin behaviour with tests against `ncftest` or the CLI fake API. A bug fix starts with a failing test.
- Reproduce a review finding before fixing it.
