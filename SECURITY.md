# Security Policy

## Supported Versions

Security fixes go into the latest release. Only the latest minor version is
supported, unless a release note says otherwise.

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability, credential exposure or
unsafe behaviour. Report privately through GitHub private vulnerability
reporting: <https://github.com/dvmrry/akamai-prolexic/security/advisories/new>
(also reachable from the repository's **Security** tab, **Report a
vulnerability**).

These are the reports that matter most:

- `apply` writing anything other than the reviewed plan, or leaving a partial
  change live;
- a way past the own-space checks, so a change could block the account's own
  addresses;
- credentials reaching output, logs or the repository;
- a way past the MCP front's limits: the file root, the read-only client, or a
  route to `apply`;
- API text reaching a terminal or a model unescaped.

Please include:

- the affected `prolexic` version or commit;
- the command or MCP tool and the output format involved;
- redacted sample output or a minimal synthetic reproduction.

Do not send real EdgeGrid credentials, account ids, customer names, address
space or unsanitized API output. Use documentation address ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) instead.

## Response

Reports are acknowledged within 7 days, best effort, and receive an initial
assessment with an estimated fix or risk decision within 14 days. This is a
single-maintainer project, so timelines may occasionally vary; every report is
read. Fixed vulnerabilities are disclosed publicly through GitHub Security
Advisories and identified in the release notes of the fixing release.

## Project Roles

This is a single-maintainer project: the repository owner is the only person
with privileged repository access and holds all roles: development, review
(enforced through the required CI checks rather than a second reviewer), release
approval, and security response through the private reporting channel above.

## Authorized Use

`prolexic` is intended for people and agents working with Akamai accounts they
are authorized to operate. It is unofficial and not affiliated with Akamai, so
report vulnerabilities in Akamai's own services to Akamai.
