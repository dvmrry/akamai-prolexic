## prolexic apply

apply a reviewed plan (the only command that writes)

### Synopsis

Recomputes the plan, refuses unless its digest equals --expect-digest (the digest of the plan you reviewed), then writes with the write credentials and waits for production to carry the new versions.

```
prolexic apply [flags]
```

### Options

```
      --expect-digest string     the digest of the reviewed plan (required)
      --file string              the desired file (required)
  -h, --help                     help for apply
      --interval duration        polling period while waiting (default 15s)
      --max-removals int         most entries one alias may lose in one apply; -1 for no limit (default 10)
      --no-analytics-own-space   skip Prolexic Analytics own space (protected prefixes, own AS numbers) in the checks; recorded in the plan
      --timeout duration         how long to wait for production to carry the new versions (default 15m0s)
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

