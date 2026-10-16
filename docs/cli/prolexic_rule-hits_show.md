## prolexic rule-hits show

one rule's statistics, and its time series with a window

```
prolexic rule-hits show [flags]
```

### Options

```
      --end string       window end, RFC 3339 (default: now)
  -h, --help             help for show
      --rule string      rule id (the ruleId from rule-hits list; required)
      --since duration   window ending now, e.g. 24h; exclusive with --start/--end
      --start string     window start, RFC 3339 (e.g. 2026-01-01T00:00:00Z)
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

* [prolexic rule-hits](prolexic_rule-hits.md)	 - ACL rule match statistics

