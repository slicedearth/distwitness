# DistWitness

DistWitness is a deterministic, privacy-first monitor for meaningful changes in
Python package releases. It turns bounded public metadata from PyPI and OSV into
review signals, a static dashboard, an Atom feed, sanitised JSON, and a Markdown
digest.

DistWitness does not download, install, import, unpack, execute, or scan package
code. It does not establish that a package is safe, malicious, trustworthy, or
compromised. Every finding means “change detected; review recommended in your
own context.”

The repository is prepared for a free public operating model: scheduled GitHub
Actions, workflow-internal state recovery, and a static GitHub Pages site.
Nothing is deployed merely by installing or running the project locally.

## Why this exists

Ordinary “latest version” checks answer whether a newer version exists.
Dependabot and similar tools propose dependency updates in repositories.
DistWitness instead preserves a narrow evidence trail around the selected
release itself:

- stable-version selection and yanked state;
- distribution filenames, SHA-256 digests, sizes, types, upload times, and
  Python tags;
- declared Python requirements, dependencies, licensing fields, and project
  URLs;
- per-file provenance availability and the publisher identity reported by
  PyPI;
- known OSV advisory identifiers reported for the exact selected version.

Useful contexts include a maintainer watching the packages used to build a
project, a small team reviewing release metadata before planned upgrades, and a
developer who wants an Atom subscription instead of another account or alerting
service.

## Features

- Strict YAML watchlist with PEP 503 name normalisation and duplicate rejection.
- Highest eligible PEP 440 release selection from PyPI's JSON Index API;
  pre-releases are opt-in.
- Accurate all-yanked handling without inventing an alternative version.
- HTTPS-only fixed PyPI/OSV destinations, bounded responses and retries, no
  distribution downloads.
- Distinct provenance states: `present`, `absent`, `unsupported`, `unavailable`,
  `request_failed`, and `malformed_response`.
- Fail-closed OSV handling: incomplete results cannot create advisory removals.
- Stable evidence-derived event IDs, atomic state writes, writer locking,
  corruption detection, deduplication, and retention pruning.
- Accessible generated HTML with no framework or external assets; core content
  works without JavaScript.
- A custom evidence-ledger identity and locally bundled SVG mark, with no
  borrowed brand assets or remote fonts.
- Static 20-event change pages with previous/next controls, first/last anchors,
  nearby desktop/mobile page windows, and no-JavaScript navigation.
- Retained per-source operational observations with exact run and package-check
  counts, an explicit baseline/measured-history distinction, and public health
  JSON.
- Atom, public JSON, Markdown, terminal, and GitHub Actions job summaries.
- No accounts, cookies, analytics, telemetry, external notification service, or
  visitor-side API requests.

## Deliberate non-features

The MVP has no package installation, source inspection, malware detection,
maintainer investigation, automatic blocking, issue creation, risk score,
private index support, non-Python ecosystems, webhooks, Slack, Discord, email,
database server, API server, user accounts, browser extension, machine
learning, or generated summaries.

## Architecture

The CLI loads a strict watchlist, constructs only known PyPI and OSV endpoints,
normalises compact source fields, compares them with a versioned local state
document, and writes static publication artefacts. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the data flow and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the security boundaries.
Private and public JSON versions and migration behaviour are documented in
[docs/STATE_SCHEMA.md](docs/STATE_SCHEMA.md).

Generated output is inert. The small local script only filters already-rendered
events and changes UTC timestamps to the visitor's local display; it makes no
network requests and never uses `innerHTML`.

## Requirements and setup

- Python 3.12 or later
- Network access only for `scan` and `run`

Standard `venv` and `pip` are sufficient:

```bash
git clone https://github.com/slicedearth/distwitness.git
cd distwitness
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m distwitness validate
```

For development:

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy src tests
pytest --cov=distwitness --cov-report=term-missing
```

`uv` may be used as a convenience, but DistWitness does not require it.

## Configuration

The default watchlist is a real bounded set of 25 packages across application,
transport, cryptography, ASGI, build, test, and static-analysis roles:

```yaml
project:
  title: DistWitness
  retention_days: 180
  max_packages: 50
  include_prereleases_by_default: false
  file_size_change_percent: 40
  file_size_change_min_bytes: 100000

packages:
  - name: httpx
  - name: requests
  - name: cryptography
    file_size_change_percent: 25
  - name: pydantic
    include_prereleases: false
  # See config/watchlist.yml for the complete reviewed set.
```

Package entries cannot contain endpoints, file paths, shell expressions, or
unknown keys. Duplicate names after Python-package normalisation are rejected.
The local hard limit is 100 packages; the included configuration uses a lower
default of 50. Selection criteria and the role-by-role inventory are in
[`docs/WATCHLIST_POLICY.md`](docs/WATCHLIST_POLICY.md); inclusion is not a
ranking, endorsement, or security claim.

## Commands

Both the console command and module form are supported:

```bash
distwitness validate
python -m distwitness scan
python -m distwitness build
python -m distwitness run
python -m distwitness doctor
```

Common options are `--config`, `--state-dir`, `--output-dir`, `--verbose`, and
`--no-cache`. `run --dry-run` performs collection and comparison without
writing state or generated output.

- `validate` checks the strict configuration and any saved state.
- `scan` fetches and normalises current data without persistence.
- `build` uses existing state and performs no network request.
- `run` collects, compares, persists, and builds the complete static output.
- `doctor` reports local readiness without enumerating environment variables,
  headers, or secrets.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Command completed; ordinary findings may exist |
| 2 | Configuration or command validation failed |
| 3 | Operational collection, output, or environment failure |
| 4 | Saved-state or locking failure |

Source-specific partial failures remain visible and preserve prior evidence.
If at least one package is collected and useful output can be built, an
individual source problem does not become a false finding.

## Outputs

The default paths are:

```text
state/state.json
site-output/index.html
site-output/changes/page-<n>.html
site-output/packages/<normalised-name>.html
site-output/feed.xml
site-output/data/current.json
site-output/data/events.json
site-output/data/health.json
site-output/reports/latest.md
```

State contains compact normalised metadata, retained events, run metadata, and
bounded aggregate source-health history. It does not contain descriptions,
README content, advisory bodies, request headers, tokens, package archives, or
raw API responses.

### Local preview

Serve `site-output` locally to inspect the generated overview:

```bash
python -m http.server 8080 --directory site-output
```

Then open `http://127.0.0.1:8080/`.

## GitHub Pages and scheduled operation

For a new installation, once a public `slicedearth/distwitness` repository
exists:

1. Push reviewed source to the default `main` branch.
2. In repository **Settings → Pages**, select **GitHub Actions** as the source.
3. Run the **Scheduled DistWitness scan** workflow manually.
4. Confirm the successful deployment environment and final Pages URL.
5. Inspect the downloaded deployment artefact when needed; it must contain only
   generated site assets, public JSON, reports, and `.nojekyll`.

The workflow runs automatically each day at `17:23 UTC`; the manual trigger is
for initial enablement, supervised verification, and recovery. Scheduled start
times are nominal because GitHub can delay or drop queued runs under load. The
collection job runs trusted default-branch code with read-only contents
permission. A separate deployment job receives only generated artefacts and
has narrowly scoped `pages: write` and `id-token: write` permissions, with no
repository write permission. Pull-request CI uses fixtures and performs no
required live API calls.

GitHub disables scheduled workflows in public repositories after 60 days
without repository activity. Re-enable the workflow from the Actions tab and
run `workflow_dispatch` once. Forks do not run scheduled workflows by default
and must deliberately enable Actions and Pages. Detailed recovery and rotation
procedures are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Data, privacy, and security

The documented sources are the PyPI Index API, release-specific JSON API, PyPI
Integrity API, and OSV API. Fields, terms review, polling, caching, attribution,
and correction paths are recorded in [DATA_SOURCES.md](DATA_SOURCES.md).

DistWitness itself collects no visitor data and uses no cookies, analytics, or
telemetry. Public hosting makes the repository watchlist and generated findings
public. See [PRIVACY.md](PRIVACY.md).

Remote responses are untrusted. The application uses fixed HTTPS hosts,
bounded bytes and fields, strict parsing, escaped output, local scripts only,
atomic state replacement, an advisory lock, and minimal workflow permissions.
See [SECURITY.md](SECURITY.md).

## Limitations

- Upstream metadata can be incomplete, delayed, malformed, or incorrect.
- A first run establishes a baseline; it cannot reconstruct earlier changes.
- Release discovery depends on the PyPI Index API's reported version set.
  DistWitness checks at most 20 descending eligible versions for documented
  release-specific metadata when listed versions have no retrievable files.
- PyPI provenance availability is reported metadata; DistWitness does not
  independently verify attestation signatures.
- OSV aggregates records from multiple databases with differing update and
  licensing practices. DistWitness omits advisory body text.
- A missing advisory is not proof that no vulnerability exists.
- File-size thresholds identify review-worthy magnitude, not intent.
- Scheduled operation depends on GitHub Actions, Pages, and upstream API
  availability.

DistWitness is not a substitute for dependency pinning, lockfiles, code review,
provenance verification, or a complete software-composition-analysis process.

## Contributing and licence

See [CONTRIBUTING.md](CONTRIBUTING.md) for the fixture-first development
contract. Original code is available under the [MIT License](LICENSE).
Dependency and data-source notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[DATA_SOURCES.md](DATA_SOURCES.md).

DistWitness is independent and is not endorsed by or affiliated with PyPI, the
Python Software Foundation, OSV, Google, OpenSSF, or monitored package
maintainers.
