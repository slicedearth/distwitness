# Third-party notices

Review date: 2026-07-26

DistWitness original code and styling are MIT-licensed. No third-party source
code, CSS theme, dashboard template, icon, logo, font, image, or package asset
is redistributed in the repository.

The following direct dependencies are installed by package tooling and used
under their own licences. “Redistributed” below means copied or bundled into the
DistWitness source/site, not merely installed in a development environment.

## Runtime dependencies

| Package | Purpose | Licence | Source | Redistributed |
| --- | --- | --- | --- | --- |
| httpx | Bounded HTTPS client | BSD-3-Clause | <https://github.com/encode/httpx> | No |
| Jinja2 | Escaped static HTML templates | BSD-3-Clause | <https://github.com/pallets/jinja> | No |
| packaging | PEP 440 versions, requirements, and wheel tags | Apache-2.0 OR BSD-2-Clause | <https://github.com/pypa/packaging> | No |
| pydantic | Strict validated models and schemas | MIT | <https://github.com/pydantic/pydantic> | No |
| PyYAML | Safe YAML configuration parsing | MIT | <https://github.com/yaml/pyyaml> | No |
| Typer | Command-line interface | MIT | <https://github.com/fastapi/typer> | No |

## Direct build and development dependencies

| Package | Purpose | Licence | Source | Redistributed |
| --- | --- | --- | --- | --- |
| hatchling | PEP 517 build backend | MIT | <https://github.com/pypa/hatch> | No |
| build | Isolated package build verification | MIT | <https://github.com/pypa/build> | No |
| mypy | Static type checking | MIT | <https://github.com/python/mypy> | No |
| pip-audit | Python dependency vulnerability audit | Apache-2.0 | <https://github.com/pypa/pip-audit> | No |
| pytest | Test runner | MIT | <https://github.com/pytest-dev/pytest> | No |
| pytest-cov | Coverage integration | MIT | <https://github.com/pytest-dev/pytest-cov> | No |
| respx | Mock HTTP transport for tests | BSD-3-Clause | <https://github.com/lundberg/respx> | No |
| Ruff | Formatting and linting | MIT | <https://github.com/astral-sh/ruff> | No |
| types-PyYAML | PyYAML type stubs from typeshed | Apache-2.0 | <https://github.com/python/typeshed> | No |

Transitive dependencies are resolved by `pip` and are not copied into the
repository. Before release, use `pip-audit` and inspect the built wheel/sdist.

Public API data is not software dependency code. Its attribution and
redistribution constraints are documented separately in `DATA_SOURCES.md`.
