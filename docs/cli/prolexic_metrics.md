## prolexic metrics

traffic metrics per customer name

```
prolexic metrics [flags]
```

### Examples

```
  prolexic metrics --type routed:bandwidthIn --since 6h
```

### Options

```
      --customer strings   customer name (the API's contract) to query; repeatable or comma-separated (default: every in-use name)
      --end string         window end, RFC 3339 (default: now)
  -h, --help               help for metrics
      --ip string          the IP address fbm types report on (fbm types need --subnet or --ip)
      --samples int        number of data points to return (default 100)
      --since duration     window ending now, e.g. 24h; exclusive with --start/--end (default 24h0m0s)
      --start string       window start, RFC 3339 (e.g. 2026-01-01T00:00:00Z)
      --subnet string      the subnet fbm types report on (fbm types need --subnet or --ip)
      --type strings       SERVICE:METRIC, or fbm:METRIC:PROTOCOL (repeatable or comma-separated); e.g. routed:bandwidthIn, fbm:bandwidth:total
```

### Options inherited from parent commands

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --ca-bundle string       PEM file of extra root CAs to trust, e.g. a TLS-inspecting proxy's (); verification is never turned off
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: auto (text on a terminal, else json), json or text (default "auto")
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic](prolexic.md)	 - A CLI for Akamai Prolexic

