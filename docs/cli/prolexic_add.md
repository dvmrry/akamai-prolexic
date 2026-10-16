## prolexic add

add entries to an alias in the desired file (offline)

### Synopsis

Adds entries, with ticket, reason and date metadata, to one alias of the desired file and rewrites it in canonical form. Offline validation runs first; on any error, or a warning about an added entry, nothing is written.

```
prolexic add --file F <alias> <entry>... --ticket T --reason R [--expires YYYY-MM-DD] [flags]
```

### Examples

```
  prolexic add --file desired.json block-v4 198.51.100.7 --ticket SEC-123 --reason scanner
```

### Options

```
      --expires string   YYYY-MM-DD after which the entries are flagged as expired
      --file string      the desired file (required)
  -h, --help             help for add
      --reason string    why the entries are added (required)
      --ticket string    the ticket authorising the change (required)
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

