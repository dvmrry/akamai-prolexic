## prolexic managed

managed-services ACLs and rule hits

```
prolexic managed [flags]
```

### Options

```
  -h, --help   help for managed
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
* [prolexic managed acl](prolexic_managed_acl.md)	 - a policy domain's latest managed-services ACL version
* [prolexic managed rule-hits](prolexic_managed_rule-hits.md)	 - a policy domain's rule statistics, and one rule's time series

