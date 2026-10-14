# akamai-prolexic

`prolexic` is a command-line client for [Akamai Prolexic](https://www.akamai.com/products/prolexic-solutions), over the Akamai APIs.

Unofficial: not affiliated with or endorsed by Akamai.

Early days: only `prolexic version` exists so far.

## Build

```
make build      # bin/prolexic
make install    # ~/go/bin/prolexic
make check      # gofmt, go vet, go test, gitleaks
```

## Credentials

Akamai API clients authenticate with EdgeGrid credentials, kept in `~/.edgerc`. They never go in this repo: `.edgerc` is gitignored, and `.gitleaks.toml` flags EdgeGrid tokens in commits.
