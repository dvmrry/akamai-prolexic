## prolexic export

write live editable aliases to the desired file (bootstrap, or adopt drift)

### Synopsis

Reads live state (read credentials only) and writes the editable aliases to the desired file in canonical form. A missing or empty file is bootstrapped from every editable alias; an existing file is updated to the live entries of the aliases it names, keeping their metadata.

```
prolexic export [flags]
```

### Options

```
      --all           also add editable live aliases the file doesn't name
      --file string   the desired file (required)
  -h, --help          help for export
      --role string   role for aliases no deployed rule references (deployed rules decide the rest): deny or allow (default "deny")
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

