# Watchlist policy

Review date: 2026-07-27

The default DistWitness watchlist is a bounded reference set, not a package
ranking, endorsement, vulnerability list, or claim about ecosystem importance.
Its purpose is to exercise the monitor against varied public release-metadata
surfaces while remaining small enough for sequential, respectful daily
collection.

## Inclusion criteria

A package may be included when it satisfies all of these conditions:

- it is published through the public PyPI service under a valid normalised
  project name;
- it represents a dependency, protocol surface, or development tool relevant
  to building or operating this project or comparable Python applications;
- its metadata can be observed through the same fixed PyPI and OSV endpoints as
  every other entry;
- including it does not require credentials, package downloads, code
  execution, private indexes, scraping, or a package-specific endpoint; and
- the complete watchlist remains within the configured and hard package limits.

Selection deliberately covers several roles so the operational record is not
dominated by one release pattern:

| Role | Included packages |
| --- | --- |
| Application contracts and rendering | `httpx`, `pydantic`, `jinja2`, `typer`, `packaging`, `PyYAML` |
| Transport and trust-store dependencies | `requests`, `urllib3`, `certifi`, `idna`, `anyio`, `httpcore` |
| Cryptography and TLS interfaces | `cryptography`, `pyOpenSSL` |
| CLI and terminal presentation | `click`, `rich` |
| ASGI framework and serving surfaces | `fastapi`, `starlette`, `uvicorn` |
| Build, test, and static analysis | `build`, `wheel`, `pytest`, `pluggy`, `ruff`, `mypy` |

## Exclusion and review

The list does not attempt to cover all of PyPI. Download counts, social
popularity, security reputation, maintainer identity, and advisory presence are
not automatic inclusion or exclusion rules.

Review the list when collection time approaches the scheduled workflow limit,
an entry is renamed or removed, or a role becomes overrepresented. A package
removal is a reviewed source change; retained historical events follow the
normal retention and correction policy in
[`OPERATIONS.md`](OPERATIONS.md).

New entries establish real baselines on their first successful observation.
DistWitness must not backfill synthetic findings or describe the absence of
prior history as evidence that no earlier changes occurred.
