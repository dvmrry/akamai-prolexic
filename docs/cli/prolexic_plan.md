## prolexic plan

diff the desired file against live and validate it

### Synopsis

Reads live state (read credentials only), diffs it against the desired file, runs every offline and live check, and prints the plan with its digest. --out saves the plan's JSON to a file (for apply --plan and verify --plan) and shows the text on stdout, from the same run.

```
prolexic plan [flags]
```

### Options

```
      --exit-code                exit 7 when the plan has changes (drift)
      --file string              the desired file (required)
  -h, --help                     help for plan
      --max-removals int         most entries one alias may lose in one apply; -1 for no limit (default 10)
      --no-analytics-own-space   skip Prolexic Analytics own space (protected prefixes, own AS numbers) in the checks; recorded in the plan
      --out string               also save the plan's JSON to this file; stdout shows text unless --format json
```

### Options inherited from parent commands

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: auto (text on a terminal, else json), json or text (default "auto")
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic](prolexic.md)	 - A CLI for Akamai Prolexic

