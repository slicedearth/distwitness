# Security policy

## Supported versions

DistWitness is pre-release software. Security fixes are applied to the current
`main` branch; no older release line is currently maintained.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting facility for
`slicedearth/distwitness` when it is enabled:

<https://github.com/slicedearth/distwitness/security/advisories/new>

If private reporting is not enabled, open a minimal GitHub issue asking for a
private reporting channel. Do not include exploit details, credentials, tokens,
private watchlists, or other sensitive material in a public issue.

Reports should identify the affected version/commit, impact, reproducible steps,
and any proposed mitigation. Receipt and remediation timelines depend on
maintainer availability; no personal email reporting address is published.

## Security boundary

DistWitness never downloads, installs, imports, unpacks, or executes monitored
packages. It constructs only fixed PyPI and OSV endpoints, follows only bounded
allowlisted redirects, applies response/field limits, escapes generated output,
and atomically replaces validated compact state under a writer lock.

The project reports metadata changes and known advisory records. It is not a
malware scanner, trust service, package sandbox, or proof of safety.

See `docs/THREAT_MODEL.md` for assets, threats, mitigations, residual risk, and
workflow trust boundaries.
