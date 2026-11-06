# Design notes

How the code is laid out, and every place where it extends or interprets the
brief. Anything marked **verify** is a guess about live behaviour that needs
checking against a real account.

## Layout

| package | owns |
| --- | --- |
| `internal/apperr` | the error model every layer shares: kinds (a public contract) and upstream detail |
| `internal/textsafe` | which characters count as invisible; output escapes them, the desired file and the repo refuse them |
| `internal/output` | one Document per command; JSON by default, text with `--format text` or `PROLEXIC_FORMAT=text` (never guessed from a terminal: agent harnesses and CI may give one); the error document |
| `internal/jsonschema` | schemas derived from Go types; `TestSchemas` keeps `schemas/` in step |
| `internal/edgegrid` | credentials (env, then `.edgerc`) and EG1-HMAC-SHA256 signing, pinned by Akamai's published vectors |
| `internal/akamai` | the one HTTP transport: signing, lenient decoding, both problem shapes, retry policy, ambiguity marking |
| `internal/analytics` | Prolexic Analytics v2 client, fan-out over customer names, the propagation-check join |
| `internal/ncf` | the desired-state model: entries, desired file, checks, changes to the file (add and remove, and when one may be written; export from live), plan, apply, and the `Store` port |
| `internal/ncf/ncfapi` | `Store` over HTTP (NCF v2: versioned aliases, activation, BIG multipart upload) |
| `internal/ncf/ncfanalytics` | `LiveOwnSpace` over Prolexic Analytics: protected prefixes and own AS numbers, fetched once per plan |
| `internal/ncf/ncftest` | an in-memory versioned `Store` with fault injection |
| `internal/cli` | the command tree and wiring |
| `internal/hygiene` | keeps globally routable addresses and invisible characters out of tracked files, non-ASCII letters out of Go identifiers, and the layer rules below |

## Layers

The code is in three layers, so that other fronts (an MCP server, possibly a Terraform provider) can reuse it later without the CLI.

| layer | packages | does |
| --- | --- | --- |
| **SDK** | `akamai`, `edgegrid`, `analytics`, `networkhealth`, `ncf`, `ncf/ncfapi`, `ncf/ncfanalytics`, `ncf/ncftest`, plus `apperr` and `version` | API access and domain logic. Returns Go values and errors; never prints, never picks exit codes. |
| **operations** | `internal/ops` (every command but `doctor` and `version`, which describe the CLI itself) | One operation per command: input → Document. Resolves customer names, reports failed names, sorts, validates. |
| **fronts** | `internal/cli` (Cobra), `internal/mcpfront` (MCP tools over stdio), `internal/output` (rendering) | Parse their own input format, call an operation, render, map errors to exit codes. |

- **Dependencies point down only.** SDK packages never import `cli`, `output`, `jsonschema` or Cobra, and only `cli` and `internal/tools` import Cobra. `internal/hygiene` tests this.
- Everything stays under `internal/` while every consumer lives in this module. `internal/` only stops imports from other modules, so it carries no public-API promise. Move to `pkg/` only if a consumer must live elsewhere.
- **Operations take a `*ops.Runtime` and a typed input** and return the concrete document. A front builds the Runtime (clients over its credentials, a clock, a progress sink), maps its own input format onto the input type, and may repeat a check with a message naming its own flags; the operation owns the check. Messages in `ops` name fields, never flags (`internal/hygiene` tests this).
- **Defaults belong to the fronts.** An operation never turns an empty or zero input into a default: it can't tell a value left out from one given explicitly, and a script passing `--expect "$X"` with `$X` empty must get an error, not a `present` check. The CLI takes its flag defaults from constants `ops` exports; an MCP front puts the same ones in its tool schemas. The one exception is the time window: `Window` is passed only when given, so an absent window takes the operation's default.

### Errors

One error model, shared by every layer. Each layer has one job with it:

- **The SDK classifies, at the source.** HTTP status → kind, and an ambiguous write is marked where it happens. It attaches the upstream detail: status, `incidentId`, `errorPaths`.
- **Operations add context and decide policy.** For example, "a 404 here is an empty window" (`apperr.IsNotFound`), or "a failed name is reported, not fatal". Wrapping keeps the kind; reclassifying is rare and deliberate. Cancellation always wins.
- **Fronts translate, at the edge.** The CLI maps kind → exit code; an MCP server would map it to a tool error. The exit-code numbers appear in one place.
- **Outcomes are not errors.** "`routed check` not satisfied", "some names failed" and plan findings are results: they belong in the document, and the CLI turns them into exit codes. Another front returns them as data. Such a document has an `Outcome()` derived from its own fields. The operation returns the document with no error, and the CLI runner turns the outcome into the exit code. `apply` is the exception: its refusals and failures are real errors, returned with a report of what happened.

### Input validation

Types guarantee shape, not values: a `string` can be `..`, and a start time can come after the end. So input is checked in three tiers:

1. **Fronts** check their own format: flag syntax and flag combinations, or an MCP server's input schema. This gives early, friendly errors, but a front is never the only check.
2. **Operations and the SDK** parse input into types that can't hold an invalid value (`netip.Prefix`, a window, a packet list, a path segment). This is the authoritative check, and every front runs it.
3. **The transport** backstops whatever is safety-critical, whoever the caller: clean paths only, writes never re-sent, ambiguous writes marked, and read-only clients refuse writes.

A check lives at the lowest layer that has the information. Higher layers may repeat it for a better message, but never own it. The write-path invariants already work this way: they live in `ncf`, so any front that calls the core gets them.

## Credentials

- Two sections: reads use `--section` (default `default`), writes use `--write-section` (default `write`). Only `apply` resolves the write section, so a PR build without write credentials can run everything else.
- The environment wins, using Akamai's convention: `AKAMAI_HOST`… for `default` and `AKAMAI_WRITE_HOST`… for `write`. A partly set environment is an error, not a fallback to `.edgerc`.
- `doctor` prints neither values nor the API host, because the host embeds a token. It shows only whether `HTTPS_PROXY` is set, never its URL.

## Transport

- **Extension:** "retry only GETs" becomes "retry only reads". The Analytics routed endpoints are POSTs that only query, marked `ReadOnly`, so they retry like GETs and are never ambiguous.
- A write that fails with a transport error, a 5xx or a cancellation after sending is marked `ambiguous`. Callers prove the outcome by reading; they never resend.
- **Proxy and TLS.** The transport follows `HTTPS_PROXY`/`NO_PROXY` (Go's `ProxyFromEnvironment`), with no PAC support. `--ca-bundle` adds a PEM bundle to the system roots for a TLS-inspecting proxy, through `akamai.Options.RootCAs`. There's deliberately no way to turn verification off. A certificate that doesn't verify, or a proxy's 407, fails without retrying.
- **Read-only clients.** Every command except `apply` gets a client built with `ReadOnly`. It refuses any request that isn't a read (a GET, or marked `ReadOnly`) before sending, as a bug. Only `apply` builds a write client, from the write section.
- Status → error kind: 401/403 → `credentials`; 404 → `not_found`; 409/412 → `conflict`; everything else → `upstream`. The CLI maps kinds to exit codes in one table (`internal/cli/exit.go`).
- **Errors on stderr are text** (`prolexic: <message>`, plus an `upstream:` line with the method, path, status, error code and incident id when an API call failed). They are JSON (`prolexic.error.v1`) only with an explicit `--format json`: stderr is read by people, in a CI log or a terminal, and the stdout document plus the exit code are the contract. A usage error is one line that names the `--help` to run, not the whole usage.
- An expired deadline exits 5 (upstream), not 1. Responses over 16 MB fail. Error documents keep the gateway's `incidentId`.
- The tool reports what it reads, unredacted. Keeping account data out of the repo is the maintainers' job (`internal/hygiene` and the local commit guard), not the tool's. Only credential values are never printed.

## Desired file (`prolexic.desired.v1`)

```json
{
  "$schema": "optional editor reference",
  "schema": "prolexic.desired.v1",
  "accountId": "…",
  "ownSpace": {"prefixes": ["…"], "aliases": ["protected-dst"]},
  "aliases": [
    {
      "name": "block-v4",
      "id": 101,
      "type": "SOURCE",
      "role": "deny",
      "entries": ["192.0.2.0/24", {"cidr": "198.51.100.7/32", "ticket": "…", "reason": "…", "added": "YYYY-MM-DD", "expires": "YYYY-MM-DD"}]
    }
  ]
}
```

- **Extension: `role` (`deny`, `allow` or `destination`)** per alias: what the deployed rules use it for. `deny` is the source of a deny rule (who is blocked; own-space checked), `allow` the source of a permit rule (who is let through), `destination` a rule's destination (where it applies: the addresses being protected, which belong in `ownSpace.aliases`; own space counts both an own-space alias's live entries and, when the file manages it, the entries the file is about to give it, so a deny entry can't cover a prefix the same apply adds; `export` declares them, and `plan` warns `own_space_undeclared` about a protected-destination alias a rule uses that the file doesn't declare). Plan derives the role from the deployed rules: an alias is deny-side when a deployed `deny` rule uses it as its source (live names a source alias `SRC::<account>::<name>`, a destination alias bare; matching the name or a `::<name>` suffix covers both). The derived role wins, the plan reports `roleSource: rules`, and a file whose `role` disagrees fails with `role_mismatch`. An alias no deployed rule references keeps the file's role for the record (`roleSource: file`), but is own-space checked as deny whatever that role says: nothing verifies it, and an edit to the file must not switch the checks off. `export` writes the derived role. A DIPA alias is never own-space checked: it lists destinations. A rule only counts when it names the alias (case-insensitively), and only `deny` or a known permit word (`permit`, `accept`, `allow`) is understood. If deployed rules reference an alias but its side can't be read (unknown address form, unknown action, a rule without parsed details), or one of those rules can't be read at all (missing from the deployed version, or an index two rules share), or a deployed rule names the alias without being among its rule indexes (the alias list and the rules are separate reads, and a deployment can land between them), the side is `unverified`: plan warns `role_unverified` and applies own-space checks whatever the file says. Only a verified derivation can relax them. A protected-destination (DIPA) alias that a deployed rule denies as a source is an error (`dipa_deny_source`): it would block traffic from our own addresses. One whose side can't be read is an error too (`dipa_unverified`): checked as deny means nothing for an alias that is never own-space checked. Every deployed rule counts: one at an index two rules share, and one the API gave no parsed form (kept with its text; remarks are skipped). An address is never read as an alias reference, though an IPv6 literal can end in a name (`2001:db8::cafe`).
- **Extension: `ownSpace`** holds the static list and names the protected-destination alias(es), which must be DIPA aliases. Plan reads those aliases' live entries; an entry it can't read is an error.
- The canonical form is: keys in a fixed order that reads top-down in a diff (each alias's name, id, type and role before its entries; each entry's cidr first), aliases sorted by name, entries sorted v4 → v6 → GEO → ASN, `[]` never `null`, two-space indent and a trailing newline. `validate` fails a file that isn't byte-identical to it.
- Entries are normalised on both sides. An authored host-bits typo is rejected, while the same thing from live is masked.

## Checks

- **Bogons include the documentation ranges.** Synthetic fixtures must use them, so tests drop them from the list through `Env.Bogons`. The binary can't do that.
- `GEO::` and `ASN::` are accepted on `SOURCE` and `BIG` aliases (techdocs); `DIPA` holds destination IPs only.
- The removal threshold is 10 entries per alias per apply. `--max-removals N` raises it and `-1` removes it.
- There is no per-alias version limit: live NCF v2 states none, and the 10 in the alias list is only the length of its `versions` summary. So there are no version-count warnings; rotation stays an explicit, separate command if it's ever needed.
- **Own space from Analytics** is the union of `metric-types` FBM `subnets` across all customer names, in use or not. The spec has no field called "protected prefixes", so **verify** that these are the right prefixes. IPv4-mapped prefixes are unmapped, like entries, so they compare with IPv4 entries. A subnet that isn't a prefix is an error (`own_space_unreadable`): it is own space nothing could check against.
  - A customer name with none produces a warning: an empty list means unknown, not "nothing protected".
  - If the lookup fails, the plan fails.
  - `--no-analytics-own-space` skips the lookup and records a warning in the plan.
- **Own AS numbers** come from the `asn` of every BGP session (all customer names). A deny-side `ASN::<ours>` entry is an `own_space` error, like an overlapping prefix: it would block our own network. There is no override; if ingress anti-spoofing (denying our own space as a source) is ever wanted, add a per-entry acknowledgement for prefixes and ASNs together. `GEO::` entries aren't checked: blocking a country our space sits in isn't clearly a mistake.

## Plan and apply

- The digest is sha256 over the plan's settings (the removal limit, and whether live own space was skipped) and each alias's id, name, `activeVersion`, add/remove sets, `desiredHash` (sha256 over the alias's expected entries after apply, canonical and sorted), `role` and `roleSource`: the side the own-space checks ran on is part of what was reviewed, so a side that changes before apply moves the digest. Metadata isn't included because it never reaches the API.
- Apply runs in three phases, so no alias is activated unless every alias's new version verified:
  1. For each alias: check the conflict token, create a version, re-read it and compare it to desired.
  2. Activate all of them.
  3. Wait until `prodVersion` matches for all, the ACL deployment reports no failed rules, no ruleset at or after the production version is FAILED, and nothing is processing.
- An ambiguous create is resolved from the version list:
  - no new version: it didn't land, and re-running is safe;
  - exactly one: it landed and goes on to verification, if it carries this apply's comment and source version (a SOURCE or DIPA version that doesn't is another writer's: exit 8). BIG uploads carry no marker, so for them entry verification is the only check;
  - more than one: a concurrent writer (exit 8).
- **NCF v2:** the `Store` port uses the brief's vocabulary (`activeVersion`, `prodVersion`, the version list, create, activate). Version ids are opaque strings (live v2 uses `"V1"`). The v2 spec is login-only (kept in `spec/`, not vendored). v2 has no get-one-alias, so `GetAlias` lists aliases and reads the listed active version by id (live `/versions/active` carries no entries); create sends `isActive: false` and `sourceVersion` (BIG uploads are multipart and may activate on arrival).
- **Progress on stderr.** `apply` and `routed check --wait` write one `prolexic: …` line per step to stderr (created, activated, each poll while waiting with elapsed time, in production), so a wait of several minutes in CI doesn't look like a hang or trip a no-output timeout. stdout keeps its one document, and an error document, if any, follows the progress lines on stderr. The SDK reports structured steps (`ApplyOptions.Progress`), and each front decides how to show them.
- **Verify after apply.** `prolexic verify --plan plan.json` reads every alias in the saved plan fresh and checks the plan's end state: added entries live, removed entries gone, exactly the expected set (`desiredHash`, so an unchanged entry swapped for another is caught), production carrying the active version (and still carrying an alias the plan saw in production), and a healthy, settled ACL deployment. It exits 7 otherwise, and refuses a plan whose digest doesn't match its aliases (edited or truncated). A pipeline carries one artifact: `plan --out plan.json --format text` on the PR (text for the reviewer on stdout, JSON in the file, from one run), then `apply --plan plan.json` (`ncf.Apply` takes the reviewed digest from the plan, and refuses it for another or changed desired file, another account or other settings; a bare digest is not accepted, since with nothing to write it couldn't tell a re-run after success from another file), then `verify --plan plan.json`. The core is `ncf.Verify`, read-only.
- **An alias changes as a whole.** A changed alias gets one new version holding its complete final entry set, then one activation. The API is never sent entry-level adds or removes. So splitting a block into smaller ones, and leaving one out, has no intermediate state (`TestApplySplitIsOneVersionOneActivation`). Any other front must keep this. A Terraform provider would model an alias's entry set as one resource, never one resource per entry: per-entry resources turn one change into serial, unordered calls.
- **Across aliases there is no atomicity (open).** Activation is per alias, in desired-file order with BIG aliases last, and each alias reaches production on its own. A change that moves space between aliases has a window in between. Moving a block from one deny alias to another opens a hole if the removal lands first; landing the addition first briefly double-blocks it, which fails closed. The apply result times each change: `activatedAt` and `productionAt` per alias (accurate to the poll interval), shown as TO PRODUCTION in text. The first live apply measures the window, and that decides whether this gap is worth more than a warning. For now `plan` warns (`cross_alias_move`) when space leaves one deny-side alias while another gains it, and the reviewer splits the change into two applies, addition first. Such moves need two deny-side aliases. Undecided until a setup needs them: ordering activations inside one apply (deny-side additions first, with a production wait between the groups), and the order for allow-side aliases.
- **Entries stay off the wire:** v2's alias list carries no entries (v1 listed them, managed aliases included), so `plan`, `status` and `export` never download an Akamai-managed alias's entries.

- **Rollback depth (deliberate):** a rollback re-activates the version the apply replaced, but doesn't re-verify it (it was live before, and verified by its own apply) or wait for production. An unhealthy deployment after production carries the new versions is reported (exit 5), not rolled back: the fault may not be ours, and the reviewed recovery is `git revert` then apply.
- Checked against the v2 spec: the BIG upload form has only `aliasName`, `ipVersion` and `file` (no `sourceVersion`, no comment, so BIG versions carry no audit comment); the JSON create's note field is `comments`, at most 255 characters; the version list takes `size` up to 100.

## add and remove

- These commands write either the canonical file or nothing. Any error blocks the write, and so does a warning about an entry being added. Warnings about untouched entries (for example an unrelated expiry) are reported but don't block.
- `remove` records the ticket in its result document; the removed entry's metadata goes with it.

## Analytics commands

- `routed check` joins routes to sessions on customer name and peer address, with an exact masked prefix. Exit codes:
  - 7: the expectation isn't met;
  - 4: there are no sessions to check;
  - a failed name's own code: `absent` can't be declared while a customer is unreadable.
- `events`: the API takes no time range, so `--since`/`--start`/`--end` filter on our side by span overlap.
- `attacks list` and `attacks show` return different shapes, which is why they are separate subcommands.
- A customer name containing `/` is rejected, because the path can't carry it. An explicit empty name is rejected too, before any request: dropped, it would query no names and report an empty success.

## MCP front

`internal/mcpfront` offers the operations as MCP tools over stdio (`prolexic mcp`), using the official Go SDK with its stdio transport only. Nothing listens; a networked server would be a separate decision.

- **Read-only towards the API.** `mcpfront.New` refuses a runtime with a write client, and there is no apply tool: production changes go through version control (a pull request, the reviewed plan, CI's apply). The tools that write, write local files only: the desired file, and a saved plan.
- **One contract.** A tool returns the document the CLI prints as JSON (`TestMCPReturnsTheCLIDocument` compares them byte for byte), through `internal/output`, which escapes invisible characters. An outcome (a check not satisfied, failed names) is a note beside the document, not a tool error; an error is a tool error carrying the error document (its `code` is 0: `kind` is the contract).
- **Arguments** are types of their own with JSON Schemas from `internal/jsonschema`, stating defaults and bounds. Unknown arguments are refused, and names must match exactly at every depth (Go's decoder alone would take `Prefix` for `prefix`). A value with a default is a pointer, so a value left out (the default, from the same ops constant the CLI uses) differs from one given explicitly.
- **Paths** are resolved against a root and confined to it, through symbolic links; a path that is itself a symbolic link is refused. Only `.json` files outside hidden directories (`.git`, `.github`) are reachable. The check is made before the operation opens the path, so a process that can already write in the root could swap a directory for a link in between; confinement keeps the agent's arguments in, not other local writers (an agent with its own file tools can read anything anyway). Operations get them relative (`ops.Runtime.Dir` is the root), so documents, saved plans and error messages name no local directory. A plan's output path must be new or an existing saved plan (for every front).
- **An agent's plan can only tighten checks.** CI's apply runs with the reviewed plan's settings, so the `plan` tool offers no way to skip the live own-space check and takes a removal limit only from 0 to the default. A person loosens them deliberately, with the CLI; the plan's text shows the removal limit to the reviewer.
- **One call can't take the session down:** tool calls run concurrently (the CLI's client wiring is safe for that), a waiting `routed_check` polls no faster than every 5s for at most an hour, at most four wait at once, and a panic, in a handler or in a fan-out query, becomes that call's (or that name's) `bug` error. Changes to files are serialised within the process (one lock, so two spellings of a file on a case-insensitive disk can't race), so two concurrent `add` calls both land. A line on stdin that isn't JSON ends the session: that's the SDK's stdio transport, and a conforming client never sends one.

## Not built yet

- Alias rotation as an explicit command.
- Network Health targets: create, update and delete (read-only `targets list` and `targets show` exist; targets are per account, and the spec has no paging).
- Nothing from the Analytics spec is left unread: `metrics`, `time-series`, `scrub-centers` and `protected` exist (`protected` shows plan's own space: FBM subnets and BGP-session ASNs per customer name; **verify** the metrics point shapes and the `/time-series-data` facet keys against a live account).
