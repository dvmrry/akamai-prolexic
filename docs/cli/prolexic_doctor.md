## prolexic doctor

show which credentials resolve (offline unless --live)

### Synopsis

Shows which credentials resolve for the read and write sections, and whether a proxy is configured. It never prints a credential value or the API host. It is offline unless --live is set; --live also makes one read per API (NCF, Analytics, Network Health) with the read credentials and reports which APIs they can use.

```
prolexic doctor [flags]
```

### Options

```
  -h, --help   help for doctor
      --live   make one read per API with the read credentials and report which APIs they can use
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

