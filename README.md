# akamai-prolexic

`prolexic` is a command-line client for [Akamai Prolexic](https://www.akamai.com/products/prolexic-solutions), over the Akamai APIs.

Unofficial: not affiliated with or endorsed by Akamai.

It does two things:

- **Network Cloud Firewall alias entries as reviewed desired state.** A machine-owned JSON file in git is the intent, and live is the state. `plan` diffs them, `apply` writes a reviewed plan, and `verify` reads the result back.
- **Read-only visibility** across Prolexic: firewall aliases, ACLs and rule hits; Routed BGP sessions, routes and tunnel health; attacks, events and traffic; Network Health targets.

The read side stands on its own. With read credentials only, `plan --exit-code` on a schedule is drift detection against a reviewed file, and `export` adopts changes made in Control Center.

See [docs/design.md](docs/design.md) for the model and the decisions behind it, [docs/runbook.md](docs/runbook.md) for what to do when something fails, and [docs/cli/](docs/cli/prolexic.md) for every command and flag (`prolexic <command> --help` shows the same).

## First run

```
prolexic doctor --live        # which credentials resolve, and which APIs they can use
prolexic export --file desired.json   # start the desired file from live
prolexic validate --file desired.json
```

## Making a change

Edit the desired file with `add` and `remove` (they keep it canonical and record the ticket), open a PR, then:

```
# on the PR: the reviewer reads the text; the JSON is the artifact
prolexic plan --file desired.json --out plan.json

# after merge: takes the reviewed digest from the artifact, writes, waits for production
prolexic apply --file desired.json --plan plan.json

# then: an independent read-back of the plan's end state
prolexic verify --plan plan.json
```

`apply` re-plans and refuses (exit 7) if live moved since the review. It writes one new version per changed alias, holding the alias's complete final entry set, so an alias never passes through a half-changed state. It then waits for production, printing progress on stderr. Akamai documents a deployment window of up to about ten minutes. `apply` is the only command that writes, and the only one that uses the write credentials.

## Output and exit codes

stdout carries one document. It's JSON when stdout isn't a terminal (or with `--format json`), and every document names its schema (`schemas/`) and says when and by which version it was made. stderr is text for people: progress lines, and on failure one `prolexic:` line (JSON only with `--format json`).

The exit codes are a contract:

| code | meaning |
| --- | --- |
| 0 | ok |
| 1 | bug |
| 2 | usage |
| 3 | credentials |
| 4 | not found or unsupported |
| 5 | upstream failure |
| 6 | validation |
| 7 | drift, or the plan's digest moved |
| 8 | conflict (another writer) |
| 130 | cancelled |

## Build

```
make build      # bin/prolexic
make install    # ~/go/bin/prolexic
make check      # gofmt, go vet, go test, gitleaks
make schemas    # regenerate schemas/ after changing a document type
make docs       # regenerate docs/cli/ after changing a command or flag
```

## Credentials

Akamai API clients authenticate with EdgeGrid credentials. These come from the environment first (`AKAMAI_HOST`, … for the read section; `AKAMAI_WRITE_HOST`, … for the write section), then from `~/.edgerc`. Only `apply` uses the write section. Every other command gets a read-only client that refuses to send a write.

Credentials never go in this repo: `.edgerc` is gitignored, `.gitleaks.toml` flags EdgeGrid tokens, and `internal/hygiene` fails on globally routable addresses in tracked files.

## License

prolexic is source-available under the [Business Source License 1.1](LICENSE).

- **Free:** any individual or organization using it for its own purposes, including in production on its own Akamai accounts.
- **Needs a commercial license:** offering it, or a service built on it, to customers or other third parties for a fee. That includes managed or hosted services, consulting or managed security services delivered to clients, and bundling it into a commercial product. Contact the licensor through [github.com/dvmrry](https://github.com/dvmrry).
- **Becomes Apache-2.0:** each version converts to the Apache License 2.0 on 2030-10-15, or four years after that version is published, whichever comes first.

The vendored Akamai API specifications in `api/akamai-apis/` and the EdgeGrid signing test vectors stay under their own Apache-2.0 license.
