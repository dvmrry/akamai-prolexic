## prolexic managed acl

a policy domain's latest managed-services ACL version

```
prolexic managed acl [flags]
```

### Options

```
  -h, --help                   help for acl
      --policy-domain string   policy domain (required)
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

* [prolexic managed](prolexic_managed.md)	 - managed-services ACLs and rule hits (read-only)

