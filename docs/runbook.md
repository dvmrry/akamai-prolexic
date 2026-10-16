# Runbook

What to do when `prolexic` stops a change. Find the exit code, then the message (the line starting `prolexic:` on stderr). Each entry says what happened, whether it's about your change, and what to do next.

**Two things are always true:**
- Only `apply` writes. A failure in `plan`, `verify`, or any read command changed nothing.
- `apply` never leaves half a change live on purpose. Each alias changes as a whole: a new version holding the alias's complete entry set, activated in one step. If an alias fails, every alias this apply already activated is put back, unless someone else changed it in the meantime.

The CI flow these entries assume:

```
PR:     prolexic plan   --file desired.json --out plan.json
merge:  prolexic apply  --file desired.json --plan plan.json
then:   prolexic verify --plan plan.json
```

## Before the first change

- **Run `prolexic doctor --live`.** It shows which credentials resolve and which APIs they can use: NCF, Prolexic Analytics, Network Health.
  - `analytics FAILED (credentials)` means `plan` will fail too, because plan reads your own space from Analytics. Ask for Analytics read access on the API client. Until then, `plan --no-analytics-own-space` works, and says in a warning that it skipped that check.
- **`apply` needs the write credentials** (the `write` section, or `AKAMAI_WRITE_*`). Every other command works without them.

## Behind a corporate proxy

- **Proxy:** prolexic follows `HTTPS_PROXY` and `NO_PROXY` (or their lower-case forms), and nothing else. There's no PAC file support: resolve the PAC once and set `HTTPS_PROXY` to the proxy it picks for the Akamai API hosts.
- **Proxy sign-in:** Basic auth works in the URL (`http://user:pass@proxy:8080`). NTLM or Kerberos (Negotiate) doesn't. Run a local helper that does the corporate sign-in, such as `px` or `cntlm`, and point `HTTPS_PROXY` at it (e.g. `http://127.0.0.1:3128`). A proxy asking for credentials (HTTP 407) fails at once and isn't retried.
- **TLS inspection:** if the proxy re-signs HTTPS, declare its CA with `--ca-bundle ca.pem` or `PROLEXIC_CA_BUNDLE=ca.pem`. It's a PEM file, which may hold several certificates. They're trusted in addition to the system roots, and verification is never turned off. Without it, every API command fails with "the server's certificate isn't trusted".
- **Check it:** `prolexic doctor --live` shows whether `HTTPS_PROXY` is set, how many certificates the bundle added, and whether each API answers.

## Exit 2: usage

The command line is wrong: a missing flag, an unknown command, a bad value. The message names the `--help` to read. Nothing was contacted.

## Exit 3: credentials

The credentials don't resolve, or the API refused them (401/403). Run `prolexic doctor --live` to see which API. If it's only `acl test` that fails, that endpoint needs a different API grant from the read key.

## Exit 5: upstream (Akamai's side, or the wait ran out)

| message contains | what it means | what to do |
| --- | --- | --- |
| `the new versions are active and production should follow; re-run apply to keep waiting` | Your change is live (active). Production hadn't caught up within `--timeout`. Akamai documents up to about ten minutes. | Re-run the same `apply`. With nothing left to write, it only waits. Then run `verify`. |
| `the ACL deployment is still processing … re-run apply to keep waiting` | Production carries your versions; Akamai is still settling the ACL. | Re-run `apply`, then `verify`. |
| `the ACL deployment is unhealthy` | Akamai reports failed rules, or a FAILED ACL version at or after production. **This may not be your change.** Any recent ACL problem on the account fails this check. | Run `prolexic acl deployment` to see what failed. If your aliases look right (`prolexic status`), raise it with Akamai support and give them the incident id from the `upstream:` line. Don't keep retrying. |
| `activated outside this apply` | An alias you didn't change is lagging in production: someone else activated it. | Not yours. `prolexic status` shows which alias, and the team that changed it should know. |
| `the activation of … was accepted, but … is still active: it didn't take effect` | Akamai accepted the activation but the alias stayed on its old version. Nothing changed for traffic. | Check `prolexic aliases versions --name X`, then re-run `apply`. It re-uses the version it already created. If it repeats, raise it with Akamai support. |
| `create a version of X: it did not land; safe to re-run` | A request failed, and `prolexic` proved nothing was created. | Re-run `apply`. |
| `create a version of X: unknown whether it landed … check status before re-running` | A request failed, and `prolexic` couldn't prove the outcome. | Run `prolexic aliases versions --name X`. Re-run `apply`: it re-uses its own earlier version if there is one, and never creates a second. |
| `doesn't hold the desired entries; it was left inactive` | Akamai stored a version with different entries from the ones sent. Nothing was activated. | Re-run `apply` once. If it repeats, raise it with Akamai support. |
| `not rolled back; check each alias by hand` | Something failed, and putting an alias back also failed. **The one case that needs a person.** | For each alias named: `prolexic aliases versions --name X` shows which version is active. Re-activate the version listed as `from` in the apply output in Akamai Control Center (Network Cloud Firewall → aliases), or re-run `apply` to finish the change. Tell whoever owns the change. |
| `activated on upload … re-activating … failed: fix it by hand` | A BIG alias went live as it uploaded (Akamai does that), verification then failed, and putting it back failed. | As above, for that alias. |

The `upstream:` line under the message gives the API call, the HTTP status and, when Akamai sent one, an incident id. Include it in any support ticket.

## Exit 6: validation

The desired file or the plan has errors. Nothing was written. The findings say which alias and entry. The common ones:

| finding | means |
| --- | --- |
| `own_space` | A deny entry would block our own addresses or AS. Remove or narrow the entry. |
| `removal_threshold` | One alias would lose more entries than the limit (10). That's usually a truncated or mistaken file. If it's really intended, raise the limit with `--max-removals`. |
| `role_mismatch` | The file's `role` disagrees with how the deployed ACL uses the alias. Fix the file's role. `export` writes the right one. |
| `not_canonical` | The file was hand-edited. Run `prolexic fmt --file desired.json` and review the diff. |
| `invisible_character` | A field holds a character that doesn't show (a zero-width space, a bidi override), usually from a copy-paste. The message names the field and the code point. Retype the value. Zero-width joiners count too, so a reason can't hold a joined emoji (a family or a profession emoji) or text that needs U+200C: with the zero-width space they are the alphabet of hidden-text tricks. |

## Exit 7: drift

| from | means | what to do |
| --- | --- | --- |
| `apply`: `the plan digest moved` | Live changed between the review and the apply (someone changed an alias, or the plan file is from an older PR). **Nothing was applied.** | Re-run `plan` on the PR, review the new plan, then merge and apply again. |
| `plan --exit-code` | Live differs from the file. | Either apply the file, or `export` to adopt what changed in Control Center, and review that. |
| `verify` | Live doesn't match the plan's end state. The output lists, per alias, what's missing, what's still there, or that production lags. A deployment line means the ACL is unhealthy or still processing. | If `apply` exited 0 just before, someone changed the alias since, or the deployment changed: check `prolexic status`. If production lags, wait and run `verify` again. |
| `routed check` | Some sessions don't match `--expect` (present or absent). | See "Routed cutover" below. |

## Exit 8: conflict

Someone else is writing to the same alias. That includes `… is active, not this apply's …: someone else activated it`: another version went live while `apply` was waiting. `prolexic` stopped rather than overwrite their change. **Find out who before doing anything else.** Then re-run `plan`, review, and apply.

## Routed cutover

When prefixes move to being advertised through Akamai rather than announced by us:

1. Before withdrawing our own announcement, confirm Akamai carries the prefix on every expected session:
   ```
   prolexic routed check --prefix 203.0.113.0/24 --expect present --wait 10m
   ```
   It polls, printing one line per attempt, and exits 0 once every expected session carries it, or 7 if any still doesn't when `--wait` runs out.
2. To roll back, check the withdrawal the same way with `--expect absent`.
3. `prolexic routed sessions` and `prolexic routed routes --prefix …` show Akamai's view in detail. What the rest of the internet sees needs an outside view (public BGP looking glasses). Akamai's APIs don't show it.

Once Routed sessions exist, `plan` also checks deny entries against our own AS numbers. The `own_space_asn_unknown` warning disappears when that check is running.

## Taking over an existing account

When aliases that someone else managed (another team, a managed service, people in Control Center) move to `prolexic`:

1. **Baseline.** Run `prolexic export --file desired.json`.
   - It writes every editable alias with its live entries.
   - It writes each alias's role as the deployed rules use it (`deny`, `allow` or `destination`).
   - It declares protected-destination aliases as own space.

   Review it as a PR. `plan` against it should show no changes.
2. **Decide what own space covers.** Prolexic Analytics' protected prefixes count automatically. If some protected sites are only routed through Prolexic on demand (during an attack), decide whether the deny rules should apply to them then, and record that decision. A rule only applies to the destinations it names.
3. **Turn on the drift check** (below) before the first change, so anything still changed outside `prolexic` shows up within a day.
4. **Agree the rule:** from here, changes go through the desired file. A change made in Control Center is backfilled by whoever made it.

## Drift: changes made outside prolexic

`prolexic plan --exit-code` exits 0 when live matches the desired file and 7 when it doesn't, and lists what differs per alias. Run it on a schedule and on demand. An example GitHub Actions job (adapt it to your CI, and install `prolexic` however your pipeline builds it):

```yaml
name: prolexic drift
on:
  schedule:
    - cron: "0 6 * * *"   # daily
  workflow_dispatch: {}   # and on demand
jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: install prolexic
        run: go install ./cmd/prolexic   # or download your release build
      - name: plan --exit-code
        env:   # the read-only API client; never the write one
          AKAMAI_HOST: ${{ secrets.AKAMAI_HOST }}
          AKAMAI_CLIENT_TOKEN: ${{ secrets.AKAMAI_CLIENT_TOKEN }}
          AKAMAI_CLIENT_SECRET: ${{ secrets.AKAMAI_CLIENT_SECRET }}
          AKAMAI_ACCESS_TOKEN: ${{ secrets.AKAMAI_ACCESS_TOKEN }}
        run: prolexic plan --file desired.json --exit-code --out drift.json
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: drift
          path: drift.json
```

Read the result by exit code:
- **0:** no drift.
- **7:** live differs. The job log shows the plan as text, and `drift.json` holds it as JSON.
- **Anything else:** the check itself couldn't run (credentials, the API, a proxy). Use the sections above. It says nothing about drift.

When it reports drift:
- **The change was wanted** (someone backfilling their console work): run `prolexic export --file desired.json` to bring live into the file, and open a PR. The change gets reviewed after the fact, like any other.
- **The change wasn't wanted:** the desired file is still right. Plan and apply as usual to put live back. Find out who changed it first, since they may change it again.

Until drift is resolved, applies of other changes still work: `apply` re-plans and only writes what was reviewed. A console change made after someone's review makes their apply refuse (exit 7, "the plan digest moved") rather than overwrite it.
