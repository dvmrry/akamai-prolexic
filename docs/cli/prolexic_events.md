## prolexic events

critical events and events per customer name

### Synopsis

Critical events and events per customer name. The API has no time window for events: --since, --start and --end filter the answer, keeping events whose span overlaps the window. With none of them, every event is listed.

```
prolexic events [flags]
```

### Options

```
      --critical-only      only critical events
      --customer strings   customer name to query; repeatable or comma-separated (default: every in-use name)
      --end string         window end, RFC 3339 (default: now)
  -h, --help               help for events
      --since duration     window ending now, e.g. 24h; exclusive with --start/--end
      --start string       window start, RFC 3339 (e.g. 2026-01-01T00:00:00Z)
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

