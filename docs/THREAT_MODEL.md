# Threat model

Review date: 2026-07-26

## Scope and trust boundaries

DistWitness trusts reviewed code and configuration on the default branch. It
does not trust PyPI/OSV responses, saved state, monitored package metadata,
workflow-cache contents, generated-branch contents, network availability, or
pull-request code.

## Assets

- Integrity of generated findings and the public site
- Integrity and recoverability of cached operational state
- The GitHub Actions write token used by the publishing job
- User trust in evidence and limitations
- Availability and bounded duration of scheduled scans
- Integrity of source code, dependency resolution, and workflow definitions

## Threats and mitigations

### Metadata injection

Package names, filenames, project URLs, dependency strings, licence values, and
publisher fields could contain HTML, terminal controls, log newlines, deceptive
Unicode, or oversized values.

Mitigations:

- strict types, item counts, and field lengths;
- control-character flattening for logs and bounded persisted strings;
- Jinja autoescaping and ElementTree XML escaping;
- no untrusted `innerHTML`; JavaScript only reads `data-*` values and writes
  `textContent`;
- conservative HTTP(S)-only public URL normalisation;
- local scripts/styles and a restrictive CSP.

Residual risk: visually confusing but valid Unicode can remain. Authoritative
links and evidence fields support human review.

### Path traversal and unsafe filenames

Distribution filenames could contain separators or dot traversal; generated
paths could escape the output root.

Mitigations:

- release filenames containing `/`, `\`, `.` or `..` path forms are rejected;
- filenames are never used as local filesystem paths;
- Integrity URL path segments are percent-encoded;
- generated paths are internal constants or normalised package names and are
  resolved beneath the output root;
- stale-output deletion is limited to a prior generated manifest.

### Arbitrary outbound requests and SSRF

Configuration or redirects could target private, local, credential-bearing, or
non-HTTPS endpoints.

Mitigations:

- endpoints are constructed internally; configuration accepts no URLs;
- exact allowlist: `pypi.org` and `api.osv.dev`;
- HTTPS/default port only, no URL credentials;
- redirects are manual, revalidated at every hop, and capped;
- no distribution download URL is requested.

### Oversized, malformed, slow, or hostile responses

Mitigations:

- separate connect/read/write/pool timeouts;
- response byte and record-count limits, including an 8 MiB project Index cap;
- bounded retries with capped exponential backoff, jitter, and Retry-After;
- four-connection transport limit and sequential package collection;
- strict JSON and schema validation;
- explicit PyPI Index media-type negotiation and API-version checks;
- bounded OSV pagination/detail reads;
- no TLS verification disabling.

### Poisoned or corrupt saved state

Mitigations:

- explicit schema version and strict model validation;
- a single documented v1-to-v2 migration performed in memory before strict
  validation, with no source-file rewrite during load;
- malformed/unsupported state fails without replacement;
- unpredictable temporary files, `0600` state permissions, `fsync`, and atomic
  replacement;
- non-blocking advisory writer lock across load/compare/write;
- deterministic event IDs, retention, and deduplication.

Recovery remains an operator decision; DistWitness never silently resets
history.

### API outages, partial data, and false conclusions

Mitigations:

- source errors and freshness remain visible;
- previous snapshots are retained when PyPI cannot be refreshed;
- incomplete OSV cannot create advisory removals;
- provenance absent, unsupported, unavailable, failed, and malformed states are
  distinct;
- source-health reports expose exact bounded counts rather than inferred
  reliability scores, and distinguish an initial baseline from measured
  history;
- wording describes reported metadata and review signals, not safety or intent;
- ordinary findings do not fail scheduled operation.

### Workflow-token misuse

Mitigations:

- CI uses `contents: read`, no secrets, and no `pull_request_target`;
- checkout does not persist credentials in CI/collection;
- pull-request jobs use local fixtures and receive no publishing token;
- collection and publishing are separate jobs and artefacts;
- cached state contains no credentials, raw responses, private indexes, or
  operator data and is not treated as a confidentiality boundary;
- the Pages payload explicitly excludes state and prior state-branch paths;
- only the publishing job receives `contents: write`;
- official Actions are pinned to full commit SHAs with release-tag comments;
- the publishing job runs no project collector and copies only a generated
  artefact;
- the token is not placed in a remote URL or printed;
- concurrency permits only one scheduled publishing run;
- the generated branch is audited to exclude workflows and source.

### Workflow-cache disclosure or loss

The default-branch cache can be restored by eligible workflow contexts and may
be evicted by GitHub. It is not private archival storage.

Mitigations:

- cached state is restricted to bounded public package metadata, review events,
  aggregate source observations, and operational timestamps or diagnostics;
- source validation excludes credentials, raw responses, request headers, and
  maintainer personal fields before persistence;
- cache restore and save use unique run keys, a project-specific prefix, and a
  full-SHA-pinned official Action;
- a missing cache creates a documented new baseline without synthetic events;
- state is never copied to `gh-pages` or the generated site artefact.

### Compromised Actions or dependencies

Mitigations:

- full commit-SHA pins and Dependabot review;
- modest permissively licensed direct dependencies with upper major bounds;
- fixture-based tests, `pip-audit`, Ruff security rules, mypy, package builds,
  and dependency review;
- no unreviewed third-party Pages deployment action.

Residual risk: a pinned action or dependency can still be compromised at its
pinned revision. Changes require review and CI.

### Availability exhaustion

Mitigations:

- 50-package default and 100-package hard limit;
- at most four connections, fixed retries, bounded responses/pages/details;
- daily non-round-minute schedule;
- workflow concurrency serialisation;
- retained static output remains readable through source outages.

## Explicit non-claims

DistWitness does not prove package safety, detect malware, verify maintainers,
analyse source, establish reproducible builds, or infer intent. A high-priority
event requests prompt human review; it is not a risk score or compromise claim.
