## prolexic routed

Routed BGP sessions, routes and tunnel health

```
prolexic routed [flags]
```

### Options

```
  -h, --help   help for routed
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
* [prolexic routed check](prolexic_routed_check.md)	 - check a prefix has propagated (or gone) on every session
* [prolexic routed health](prolexic_routed_health.md)	 - healthy and total tunnels per location and router
* [prolexic routed routes](prolexic_routed_routes.md)	 - routes announced to Akamai per customer name
* [prolexic routed sessions](prolexic_routed_sessions.md)	 - BGP sessions per customer name

