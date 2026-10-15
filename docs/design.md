# Design notes

How the code is laid out, and every place where it extends or interprets the
brief. Anything marked **verify** is a guess about live behaviour that needs
checking against a real account.

## Layout

| package | owns |
| --- | --- |
| `internal/apperr` | the exit codes (a public contract) and the error type that carries them |
| `internal/output` | one Document per command; JSON off a terminal, text on one; the error document |
| `internal/jsonschema` | schemas derived from Go types; `TestSchemas` keeps `schemas/` in step |
| `internal/edgegrid` | credentials (env, then `.edgerc`) and EG1-HMAC-SHA256 signing, pinned by Akamai's published vectors |
| `internal/akamai` | the one HTTP transport: signing, lenient decoding, both problem shapes, retry policy, ambiguity marking |
| `internal/analytics` | Prolexic Analytics v2 client, fan-out over customer names, the propagation-check join |
| `internal/ncf` | the desired-state model: entries, desired file, checks, plan, apply, and the `Store` port |
| `internal/ncf/ncfapi` | `Store` over HTTP (NCF v2: versioned aliases, activation, BIG multipart upload) |
| `internal/ncf/ncftest` | an in-memory versioned `Store` with fault injection |
| `internal/cli` | the command tree and wiring |
| `internal/hygiene` | keeps globally routable addresses out of tracked files |

## Credentials

- Two sections: reads use `--section` (default `default`), writes use `--write-section` (default `write`). Only `apply` resolves the write section, so a PR build without write credentials can run everything else.
- The environment wins, using Akamai's convention: `AKAMAI_HOST`… for `default` and `AKAMAI_WRITE_HOST`… for `write`. A partly set environment is an error, not a fallback to `.edgerc`.
- `doctor` prints neither values nor the API host, because the host embeds a token. It shows only whether `HTTPS_PROXY` is set, never its URL.

## Transport

- **Extension:** "retry only GETs" becomes "retry only reads". The Analytics routed endpoints are POSTs that only query, marked `ReadOnly`, so they retry like GETs and are never ambiguous.
- A write that fails with a transport error, a 5xx or a cancellation after sending is marked `ambiguous`. Callers prove the outcome by reading; they never resend.
- Status → exit code: 401/403 → 3; 404 → 4; 409/412 → 8; everything else → 5.
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

- **Extension: `role` (`deny` or `allow`)** per alias. The brief says the own-space check applies to "deny-side" entries, but nothing in an alias says which side it is on, so the file asserts it. `export` defaults to `deny`, which means more checks rather than fewer. With NCF v2's `prodVersion.aclRuleIndexes`, plan should derive the side from live rules and reject a file whose `role` disagrees.
- **Extension: `ownSpace`** holds the static list and names the protected-destination alias(es). Plan reads those aliases' live entries.
- The canonical form is: keys sorted at every level, aliases sorted by name, entries sorted v4 → v6 → GEO → ASN, `[]` never `null`, two-space indent and a trailing newline. `validate` fails a file that isn't byte-identical to it.
- Entries are normalised on both sides. An authored host-bits typo is rejected, while the same thing from live is masked.

## Checks

- **Bogons include the documentation ranges.** Synthetic fixtures must use them, so tests drop them from the list through `Env.Bogons`. The binary can't do that.
- `GEO::` and `ASN::` are accepted on `SOURCE` and `BIG` aliases (techdocs); `DIPA` holds destination IPs only.
- The removal threshold is 10 entries per alias per apply. `--max-removals N` raises it and `-1` removes it.
- Version thresholds count the versions remaining before this apply: a warning below 3, an error at 0, and only for aliases that change.
- **Own space from Analytics** is the union of `metric-types` FBM `subnets` across all customer names, in use or not. The spec has no field called "protected prefixes", so **verify** that these are the right prefixes.
  - A customer name with none produces a warning: an empty list means unknown, not "nothing protected".
  - If the lookup fails, the plan fails.
  - `--no-analytics-own-space` skips the lookup and records a warning in the plan.

## Plan and apply

- The digest is sha256 over each alias's id, name, `activeVersion` and add/remove sets. Metadata isn't included because it never reaches the API.
- Apply runs in three phases, so no alias is activated unless every alias's new version verified:
  1. For each alias: check the conflict token, create a version, re-read it and compare it to desired.
  2. Activate all of them.
  3. Wait until `prodVersion` matches for all, the ACL deployment reports no failed rules, no ruleset at or after the production version is FAILED, and nothing is processing.
- An ambiguous create is resolved from the version list:
  - no new version: it didn't land, and re-running is safe;
  - exactly one: it landed and goes on to verification;
  - more than one: a concurrent writer (exit 8).
- **NCF v2:** the `Store` port uses the brief's vocabulary (`activeVersion`, `prodVersion`, the version list, create, activate). Version ids are opaque strings (live v2 uses `"V1"`). The v2 spec is login-only (kept in `spec/`, not vendored). v2 has no get-one-alias, so `GetAlias` lists aliases and reads `/versions/active`; create sends `isActive: false` and `sourceVersion` (BIG uploads are multipart and may activate on arrival).
- **Entries stay off the wire:** v2's alias list carries no entries (v1 listed them, managed aliases included), so `plan`, `status` and `export` never download an Akamai-managed alias's entries.

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
- Traffic metrics (`/metrics`, `/time-series-data`, `/scrub-centers`).
