## prolexic rule-hits

ACL rule match statistics

```
prolexic rule-hits [flags]
```

### Options

```
  -h, --help   help for rule-hits
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
* [prolexic rule-hits list](prolexic_rule-hits_list.md)	 - match statistics of every rule
* [prolexic rule-hits show](prolexic_rule-hits_show.md)	 - one rule's statistics, and its time series with a window

