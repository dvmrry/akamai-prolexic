## prolexic time-series

flow usage and attack traffic per destination (read-only)

```
prolexic time-series [flags]
```

### Examples

```
  prolexic time-series --destination 198.51.100.0/24 --location agr --since 2h
```

### Options

```
      --destination strings   address or CIDR block (required); repeatable or comma-separated
      --end string            window end, RFC 3339 (default: now)
  -h, --help                  help for time-series
      --location strings      data center such as mia4, or agr for all aggregated; repeatable or comma-separated (default: agr)
      --samples int           number of timestamps to return (default: all in the window)
      --since duration        window ending now, e.g. 24h; exclusive with --start/--end (default 2h0m0s)
      --source string         router type: both, access_flow (Akamai router) or border_flow (customer router) (default "both")
      --start string          window start, RFC 3339 (e.g. 2026-01-01T00:00:00Z)
      --sum                   also return the aggregatedData facet
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

