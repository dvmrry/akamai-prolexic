# akamai-prolexic

`prolexic` is a command-line client for [Akamai Prolexic](https://www.akamai.com/products/prolexic-solutions), over the Akamai APIs.

Unofficial: not affiliated with or endorsed by Akamai.

It does two things:

- **Network Cloud Firewall alias entries as reviewed desired state.** A machine-owned JSON file in git is the intent and live is the state. `plan` diffs them and `apply` writes a reviewed plan.
- **Read-only visibility** into routed BGP sessions, routes, tunnel health, attacks and events.

See [docs/design.md](docs/design.md) for the model and the decisions behind it.

## Commands

| command | does |
| --- | --- |
| `doctor` | which credentials resolve (offline; prints no values) |
| `validate --file F` | offline checks; no credentials, no network |
| `fmt --file F [--check]` | rewrite in canonical form, or fail if not canonical |
| `add --file F <alias> <entry>… --ticket T --reason R [--expires D]` | add entries, canonical rewrite, or nothing on a finding |
| `remove --file F <alias> <entry>… --ticket T` | remove entries, likewise |
| `export --file F [--all]` | live editable aliases into the desired file |
| `plan --file F [--exit-code]` | diff against live, validate, digest |
| `apply --file F --expect-digest D` | re-plan, refuse if the digest moved, apply |
| `status` | ACL deployment, aliases with active vs production version, limits |
| `routed sessions\|routes\|health` | Routed BGP sessions, received routes, tunnel health |
| `routed check --prefix P [--expect present\|absent] [--wait D]` | is P carried on every expected session |
| `attacks list\|show`, `events` | attack reports and events |

Output is JSON when stdout isn't a terminal, and every document names its schema (`schemas/`). The exit codes are a contract:

| code | meaning |
| --- | --- |
| 0 | ok |
| 1 | bug |
| 2 | usage |
| 3 | credentials |
| 4 | not found or unsupported |
| 5 | upstream failure |
| 6 | validation |
| 7 | drift, or digest moved |
| 8 | conflict |
| 130 | cancelled |

`apply` runs against NCF v2: it creates an inactive version of each changed alias (from the planned active version), verifies it, activates it, and waits for production to carry it. Write credentials are required (`--expect-digest` from a reviewed `plan`).

## Build

```
make build      # bin/prolexic
make install    # ~/go/bin/prolexic
make check      # gofmt, go vet, go test, gitleaks
make schemas    # regenerate schemas/ after changing a document type
```

## Credentials

Akamai API clients authenticate with EdgeGrid credentials. These come from the environment first (`AKAMAI_HOST`, … for the read section; `AKAMAI_WRITE_HOST`, … for the write section), then from `~/.edgerc`. Only `apply` uses the write section.

Credentials never go in this repo: `.edgerc` is gitignored, `.gitleaks.toml` flags EdgeGrid tokens, and `internal/hygiene` fails on globally routable addresses in tracked files.

## License

prolexic is source-available under the [Business Source License 1.1](LICENSE).

- **Free:** any individual or organization using it for its own purposes, including in production on its own Akamai accounts.
- **Needs a commercial license:** offering it, or a service built on it, to customers or other third parties for a fee. That includes managed or hosted services, consulting or managed security services delivered to clients, and bundling it into a commercial product. Contact the licensor through [github.com/dvmrry](https://github.com/dvmrry).
- **Becomes Apache-2.0:** each version converts to the Apache License 2.0 on 2030-10-15, or four years after that version is published, whichever comes first.

The vendored Akamai API specifications in `api/akamai-apis/` and the EdgeGrid signing test vectors stay under their own Apache-2.0 license.
