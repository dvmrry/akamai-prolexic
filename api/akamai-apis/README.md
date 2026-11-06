# akamai-apis (vendored)

Bundled OpenAPI documents from [github.com/akamai/akamai-apis](https://github.com/akamai/akamai-apis),
Apache-2.0 (see [LICENSE](LICENSE)), pinned at commit
`4521f29ef4e3dba15bbd5617365ff65d00af5049` (2026-10-05):

- `network-cloud-firewall/v1/openapi.json`
- `prolexic-analytics/v2/openapi.json`
- `prolexic-network-health/v1/openapi.json`

Re-indented with `jq .`, otherwise unchanged. The live APIs disagree with these
in places; the live API is right, and the client decodes leniently.

The CLI uses NCF v2, which is only published behind the Akamai login; its spec goes in `spec/` (never
committed).
