## prolexic verify

check a saved plan's expected end state against a fresh read (read-only)

### Synopsis

Reads every alias in a saved plan (prolexic plan's JSON) fresh and checks the plan's expected end state: each added entry is live, each removed entry is gone, the entry count is the plan's unchanged plus added (nothing extra), and production carries the active version. Run it after apply, against the plan that was reviewed. Exits 7 when anything doesn't match.

```
prolexic verify [flags]
```

### Examples

```
  prolexic plan --file desired.json --out plan.json
  prolexic apply --file desired.json --plan plan.json
  prolexic verify --plan plan.json
```

### Options

```
  -h, --help          help for verify
      --plan string   the saved plan document (JSON from prolexic plan)
```

### Options inherited from parent commands

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --ca-bundle string       PEM file of extra root CAs to trust, e.g. a TLS-inspecting proxy's (); verification is never turned off
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: json (the default), text for people, or auto (text on a terminal, else json) ($PROLEXIC_FORMAT) (default "json")
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic](prolexic.md)	 - A CLI for Akamai Prolexic

