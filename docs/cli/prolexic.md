## prolexic

A CLI for Akamai Prolexic

```
prolexic [flags]
```

### Options

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: auto (text on a terminal, else json), json or text (default "auto")
  -h, --help                   help for prolexic
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic acl](prolexic_acl.md)	 - ACL versions, rules and deployment (read-only)
* [prolexic add](prolexic_add.md)	 - add entries to an alias in the desired file (offline)
* [prolexic aliases](prolexic_aliases.md)	 - aliases and their versions (read-only)
* [prolexic apply](prolexic_apply.md)	 - apply a reviewed plan (the only command that writes)
* [prolexic attacks](prolexic_attacks.md)	 - attack reports (read-only)
* [prolexic customers](prolexic_customers.md)	 - the account's customer names (read-only)
* [prolexic doctor](prolexic_doctor.md)	 - show which credentials resolve (offline unless --live)
* [prolexic events](prolexic_events.md)	 - critical events and events per customer name
* [prolexic export](prolexic_export.md)	 - write live editable aliases to the desired file (bootstrap, or adopt drift)
* [prolexic fmt](prolexic_fmt.md)	 - rewrite the desired file in canonical form, or --check it (offline)
* [prolexic managed](prolexic_managed.md)	 - managed-services ACLs and rule hits (read-only)
* [prolexic metrics](prolexic_metrics.md)	 - traffic metrics per customer name (read-only)
* [prolexic plan](prolexic_plan.md)	 - diff the desired file against live and validate it
* [prolexic protected](prolexic_protected.md)	 - prefixes and AS numbers treated as own space, per customer name (read-only)
* [prolexic remove](prolexic_remove.md)	 - remove entries from an alias in the desired file (offline)
* [prolexic routed](prolexic_routed.md)	 - Routed BGP sessions, routes and tunnel health (read-only)
* [prolexic rule-hits](prolexic_rule-hits.md)	 - ACL rule match statistics (read-only)
* [prolexic scrub-centers](prolexic_scrub-centers.md)	 - active scrub centers (read-only)
* [prolexic status](prolexic_status.md)	 - deployment state, aliases and limits (read-only)
* [prolexic targets](prolexic_targets.md)	 - Network Health targets (read-only)
* [prolexic time-series](prolexic_time-series.md)	 - flow usage and attack traffic per destination (read-only)
* [prolexic validate](prolexic_validate.md)	 - offline checks of the desired file: no credentials, no network
* [prolexic verify](prolexic_verify.md)	 - check a saved plan's expected end state against a fresh read (read-only)
* [prolexic version](prolexic_version.md)	 - print the version

