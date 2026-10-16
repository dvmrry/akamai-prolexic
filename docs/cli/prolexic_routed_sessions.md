## prolexic routed sessions

BGP sessions per customer name

```
prolexic routed sessions [flags]
```

### Options

```
      --customer strings   customer name to query; repeatable or comma-separated (default: every in-use name)
  -h, --help               help for sessions
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

* [prolexic routed](prolexic_routed.md)	 - Routed BGP sessions, routes and tunnel health

