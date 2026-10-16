## prolexic acl

ACL versions, rules and deployment

```
prolexic acl [flags]
```

### Options

```
  -h, --help   help for acl
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
* [prolexic acl deployment](prolexic_acl_deployment.md)	 - deployment-status rulesets and which is in production
* [prolexic acl show](prolexic_acl_show.md)	 - one ACL version's rules (default: production)
* [prolexic acl test](prolexic_acl_test.md)	 - test packets against an ACL version's rules (nothing is changed)
* [prolexic acl versions](prolexic_acl_versions.md)	 - every ACL version

