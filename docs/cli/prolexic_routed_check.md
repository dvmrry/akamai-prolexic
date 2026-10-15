## prolexic routed check

check a prefix has propagated (or gone) on every session

### Synopsis

Checks, per BGP session, that the prefix is announced to Akamai (--expect present) or not (--expect absent). With --wait it keeps polling every --interval until satisfied or the time runs out.

```
prolexic routed check [flags]
```

### Examples

```
  prolexic routed check --prefix 198.51.100.0/24 --wait 10m
```

### Options

```
      --customer strings    customer name to query; repeatable or comma-separated (default: every in-use name)
      --expect string       present: every expected session carries the prefix; absent: none does (default "present")
  -h, --help                help for check
      --interval duration   time between checks while waiting (default 30s)
      --prefix string       the prefix to check (required; a bare address means /32 or /128)
      --site strings        only sessions in this data center; repeatable or comma-separated
      --wait duration       keep checking until satisfied or this long has passed (0: check once)
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

* [prolexic routed](prolexic_routed.md)	 - Routed BGP sessions, routes and tunnel health (read-only)

