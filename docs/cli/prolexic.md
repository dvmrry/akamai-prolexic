## prolexic

A CLI for Akamai Prolexic

### Synopsis

A CLI for Akamai Prolexic: Network Cloud Firewall aliases as a reviewed desired file, and read-only views across the Prolexic APIs.

A change: edit the desired file (add, remove), then
  prolexic plan --file desired.json --out plan.json     (review the plan)
  prolexic apply --file desired.json --plan plan.json   (writes; waits for production)
  prolexic verify --plan plan.json                      (reads it back)

First time: prolexic doctor --live shows which APIs your credentials can use.

```
prolexic [flags]
```

### Options

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --ca-bundle string       PEM file of extra root CAs to trust, e.g. a TLS-inspecting proxy's (); verification is never turned off
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: json (the default), text for people, or auto (text on a terminal, else json) ($PROLEXIC_FORMAT) (default "json")
  -h, --help                   help for prolexic
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic acl](prolexic_acl.md)	 - ACL versions, rules and deployment
* [prolexic add](prolexic_add.md)	 - add entries to an alias in the desired file (offline)
* [prolexic aliases](prolexic_aliases.md)	 - aliases and their versions
* [prolexic apply](prolexic_apply.md)	 - apply a reviewed plan (the only command that writes)
* [prolexic attacks](prolexic_attacks.md)	 - attack reports
* [prolexic customers](prolexic_customers.md)	 - the account's customer names
* [prolexic doctor](prolexic_doctor.md)	 - show which credentials resolve (offline unless --live)
* [prolexic events](prolexic_events.md)	 - critical events and events per customer name
* [prolexic export](prolexic_export.md)	 - write live editable aliases to the desired file (bootstrap, or adopt drift)
* [prolexic fmt](prolexic_fmt.md)	 - rewrite the desired file in canonical form, or --check it (offline)
* [prolexic managed](prolexic_managed.md)	 - managed-services ACLs and rule hits
* [prolexic mcp](prolexic_mcp.md)	 - offer the read-only operations as MCP tools to a local agent, over stdio
* [prolexic metrics](prolexic_metrics.md)	 - traffic metrics per customer name
* [prolexic plan](prolexic_plan.md)	 - diff the desired file against live and validate it
* [prolexic protected](prolexic_protected.md)	 - prefixes and AS numbers treated as own space, per customer name
* [prolexic remove](prolexic_remove.md)	 - remove entries from an alias in the desired file (offline)
* [prolexic routed](prolexic_routed.md)	 - Routed BGP sessions, routes and tunnel health
* [prolexic rule-hits](prolexic_rule-hits.md)	 - ACL rule match statistics
* [prolexic scrub-centers](prolexic_scrub-centers.md)	 - active scrub centers
* [prolexic status](prolexic_status.md)	 - deployment state, aliases and limits
* [prolexic targets](prolexic_targets.md)	 - Network Health targets
* [prolexic time-series](prolexic_time-series.md)	 - flow usage and attack traffic per destination
* [prolexic validate](prolexic_validate.md)	 - offline checks of the desired file: no credentials, no network
* [prolexic verify](prolexic_verify.md)	 - check a saved plan's expected end state against a fresh read (read-only)
* [prolexic version](prolexic_version.md)	 - print the version

