## prolexic mcp

offer the read-only operations as MCP tools to a local agent, over stdio

### Synopsis

Speaks the Model Context Protocol on stdin and stdout, for an agent's MCP client that starts prolexic as a child process. No network listener. The tools read live state with the read credentials and edit the local desired file; there is no apply: changes reach the firewall through a reviewed pull request and CI. File paths are confined to --root.

```
prolexic mcp [flags]
```

### Examples

```
  claude mcp add prolexic -- prolexic mcp --root /path/to/desired-state-repo
```

### Options

```
  -h, --help          help for mcp
      --root string   directory file paths are resolved against and confined to (default: the working directory)
```

### Options inherited from parent commands

```
      --account-key string     accountSwitchKey, overriding the credentials' account_key ($PROLEXIC_ACCOUNT_KEY)
      --ca-bundle string       PEM file of extra root CAs to trust, e.g. a TLS-inspecting proxy's (); verification is never turned off
      --edgerc string          EdgeGrid credentials file (default ~/.edgerc; $PROLEXIC_EDGERC)
      --format string          output format: json (the default), text for people, or auto (text on a terminal, else json) ($PROLEXIC_FORMAT) (default "json")
      --section string         credentials section for reads ($PROLEXIC_SECTION) (default "default")
      --write-section string   credentials section for writes; only apply uses it ($PROLEXIC_WRITE_SECTION) (default "write")
```

### SEE ALSO

* [prolexic](prolexic.md)	 - A CLI for Akamai Prolexic

