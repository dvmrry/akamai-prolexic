# Design notes

How the code is laid out, and every place where it extends or interprets the
brief. Anything marked **verify** is a guess about live behaviour that needs
checking against a real account.

## Layout

| package | owns |
| --- | --- |
| `internal/apperr` | the error model every layer shares: kinds (a public contract) and upstream detail |
| `internal/output` | one Document per command; JSON off a terminal, text on one; the error document |
| `internal/jsonschema` | schemas derived from Go types; `TestSchemas` keeps `schemas/` in step |
| `internal/edgegrid` | credentials (env, then `.edgerc`) and EG1-HMAC-SHA256 signing, pinned by Akamai's published vectors |
| `internal/akamai` | the one HTTP transport: signing, lenient decoding, both problem shapes, retry policy, ambiguity marking |
| `internal/analytics` | Prolexic Analytics v2 client, fan-out over customer names, the propagation-check join |
| `internal/ncf` | the desired-state model: entries, desired file, checks, plan, apply, and the `Store` port |
| `internal/ncf/ncfapi` | `Store` over HTTP (NCF v2: versioned aliases, activation, BIG multipart upload) |
| `internal/ncf/ncfanalytics` | `LiveOwnSpace` over Prolexic Analytics: protected prefixes and own AS numbers, fetched once per plan |
| `internal/ncf/ncftest` | an in-memory versioned `Store` with fault injection |
| `internal/cli` | the command tree and wiring |
| `internal/hygiene` | keeps globally routable addresses out of tracked files, and the layer rules below |

## Layers

The code is in three layers, so that other fronts (an MCP server, possibly a Terraform provider) can reuse it later without the CLI.

| layer | packages | does |
| --- | --- | --- |
| **SDK** | `akamai`, `edgegrid`, `analytics`, `networkhealth`, `ncf`, `ncf/ncfapi`, `ncf/ncfanalytics`, `ncf/ncftest`, plus `apperr` and `version` | API access and domain logic. Returns Go values and errors; never prints, never picks exit codes. |
| **operations** | the command bodies in `internal/cli` (for now) | One operation per command: input → Document. Resolves customer names, reports failed names, sorts, validates. |
| **fronts** | `internal/cli` (Cobra), `internal/output` (rendering) | Parse their own input format, call an operation, render, map errors to exit codes. |

- **Dependencies point down only.** SDK packages never import `cli`, `output`, `jsonschema` or Cobra, and only `cli` and `internal/tools` import Cobra. `internal/hygiene` tests this.
- Everything stays under `internal/` while every consumer lives in this module. `internal/` only stops imports from other modules, so it carries no public-API promise. Move to `pkg/` only if a consumer must live elsewhere.
- **Not yet separate:** the operations are still functions in `internal/cli` that take the CLI's `*app`. Extracting them, with a typed input per operation, waits until a second front (MCP) is scheduled.

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
- **Read-only clients.** Every command except `apply` gets a client built with `ReadOnly`. It refuses any request that isn't a read (a GET, or marked `ReadOnly`) before sending, as a bug. Only `apply` builds a write client, from the write section.
- Status → error kind: 401/403 → `credentials`; 404 → `not_found`; 409/412 → `conflict`; everything else → `upstream`. The CLI maps kinds to exit codes in one table (`internal/cli/exit.go`).
- An expired deadline exits 5 (upstream), not 1. Responses over 16 MB fail. Error documents keep the gateway's `incidentId`.
- The tool reports what it reads, unredacted. Keeping account data out of the repo is the maintainers' job (`internal/hygiene` and the local commit guard), not the tool's. Only credential values are never printed.

## Desired file (`prolexic.desired.v1`)

```json
{
  "$schema": "optional editor reference",
  "accountId": "…",
  "aliases": [
    {
      "entries": ["192.0.2.0/24", {"cidr": "198.51.100.7/32", "ticket": "…", "reason": "…", "added": "YYYY-MM-DD", "expires": "YYYY-MM-DD"}],
      "id": 101,
      "name": "block-v4",
      "role": "deny",
      "type": "SOURCE"
    }
  ],
  "ownSpace": {"aliases": ["protected-dst"], "prefixes": ["…"]},
  "schema": "prolexic.desired.v1"
}
```

- **Extension: `role` (`deny` or `allow`)** per alias. Plan derives the side from the deployed rules: an alias is deny-side when a deployed `deny` rule uses it as its source (live names a source alias `SRC::<account>::<name>`, a destination alias bare; matching the name or a `::<name>` suffix covers both). The derived role wins, the plan reports `roleSource: rules`, and a file whose `role` disagrees fails with `role_mismatch`. An alias no deployed rule references keeps the file's role (`roleSource: file`), with deny the default, so checks stay on. `export` writes the derived role. A DIPA alias is never own-space checked: it lists destinations. A rule only counts when it names the alias (case-insensitively), and only `deny` or a known permit word (`permit`, `accept`, `allow`) is understood. If deployed rules reference an alias but its side can't be read (unknown address form, unknown action, a rule without parsed details), the side is `unverified`: plan warns `role_unverified` and applies own-space checks whatever the file says. Only a verified derivation can relax them.
- **Extension: `ownSpace`** holds the static list and names the protected-destination alias(es), which must be DIPA aliases. Plan reads those aliases' live entries; an entry it can't read is an error.
- The canonical form is: keys sorted at every level, aliases sorted by name, entries sorted v4 → v6 → GEO → ASN, `[]` never `null`, two-space indent and a trailing newline. `validate` fails a file that isn't byte-identical to it.
- Entries are normalised on both sides. An authored host-bits typo is rejected, while the same thing from live is masked.

## Checks

- **Bogons include the documentation ranges.** Synthetic fixtures must use them, so tests drop them from the list through `Env.Bogons`. The binary can't do that.
- `GEO::` and `ASN::` are accepted on `SOURCE` and `BIG` aliases (techdocs); `DIPA` holds destination IPs only.
- The removal threshold is 10 entries per alias per apply. `--max-removals N` raises it and `-1` removes it.
- There is no per-alias version limit: live NCF v2 states none, and the 10 in the alias list is only the length of its `versions` summary. So there are no version-count warnings; rotation stays an explicit, separate command if it's ever needed.
- **Own space from Analytics** is the union of `metric-types` FBM `subnets` across all customer names, in use or not. The spec has no field called "protected prefixes", so **verify** that these are the right prefixes.
  - A customer name with none produces a warning: an empty list means unknown, not "nothing protected".
  - If the lookup fails, the plan fails.
  - `--no-analytics-own-space` skips the lookup and records a warning in the plan.
- **Own AS numbers** come from the `asn` of every BGP session (all customer names). A deny-side `ASN::<ours>` entry is an `own_space` error, like an overlapping prefix: it would block our own network. There is no override; if ingress anti-spoofing (denying our own space as a source) is ever wanted, add a per-entry acknowledgement for prefixes and ASNs together. `GEO::` entries aren't checked: blocking a country our space sits in isn't clearly a mistake.

## Plan and apply

- The digest is sha256 over each alias's id, name, `activeVersion` and add/remove sets. Metadata isn't included because it never reaches the API.
- Apply runs in three phases, so no alias is activated unless every alias's new version verified:
  1. For each alias: check the conflict token, create a version, re-read it and compare it to desired.
  2. Activate all of them.
  3. Wait until `prodVersion` matches for all, the ACL deployment reports no failed rules, no ruleset at or after the production version is FAILED, and nothing is processing.
- An ambiguous create is resolved from the version list:
  - no new version: it didn't land, and re-running is safe;
  - exactly one: it landed and goes on to verification, if it carries this apply's comment and source version (a SOURCE or DIPA version that doesn't is another writer's: exit 8). BIG uploads carry no marker, so for them entry verification is the only check;
  - more than one: a concurrent writer (exit 8).
- **NCF v2:** the `Store` port uses the brief's vocabulary (`activeVersion`, `prodVersion`, the version list, create, activate). Version ids are opaque strings (live v2 uses `"V1"`). The v2 spec is login-only (kept in `spec/`, not vendored). v2 has no get-one-alias, so `GetAlias` lists aliases and reads the listed active version by id (live `/versions/active` carries no entries); create sends `isActive: false` and `sourceVersion` (BIG uploads are multipart and may activate on arrival).
- **An alias changes as a whole.** A changed alias gets one new version holding its complete final entry set, then one activation. The API is never sent entry-level adds or removes. So splitting a block into smaller ones, and leaving one out, has no intermediate state (`TestApplySplitIsOneVersionOneActivation`). Any other front must keep this. A Terraform provider would model an alias's entry set as one resource, never one resource per entry: per-entry resources turn one change into serial, unordered calls.
- **Across aliases there is no atomicity (open).** Activation is per alias, in desired-file order with BIG aliases last, and each alias reaches production on its own. A change that moves space between aliases has a window in between. Moving a block from one deny alias to another opens a hole if the removal lands first; landing the addition first briefly double-blocks it, which fails closed. For now `plan` warns (`cross_alias_move`) when space leaves one deny-side alias while another gains it, and the reviewer splits the change into two applies, addition first. The account has a single deny alias today, so such moves can't happen yet. Undecided until they can: ordering activations inside one apply (deny-side additions first, with a production wait between the groups), and the order for allow-side aliases.
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
- A customer name containing `/` is rejected, because the path can't carry it.

## Not built yet

- Alias rotation as an explicit command.
- Network Health targets: create, update and delete (read-only `targets list` and `targets show` exist; targets are per account, and the spec has no paging).
- Nothing from the Analytics spec is left unread: `metrics`, `time-series`, `scrub-centers` and `protected` exist (`protected` shows plan's own space: FBM subnets and BGP-session ASNs per customer name; **verify** the metrics point shapes and the `/time-series-data` facet keys against a live account).
