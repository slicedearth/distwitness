# Contributing

Contributions should preserve DistWitness's bounded, deterministic,
privacy-first contract.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the complete local gate:

```bash
ruff format --check .
ruff check .
mypy src tests
pytest --cov=distwitness --cov-report=term-missing
python -m build
pip-audit . --strict
python -m distwitness validate
python -m distwitness build --state-dir tests/fixtures/empty-state
```

## Fixtures and source access

Ordinary tests must remain offline and use small handcrafted fixtures. Do not
copy complete PyPI responses, package descriptions, README files, advisory
bodies, or personal metadata into tests.

Live integration tests must be explicitly marked `live`, disabled by default,
bounded, and respectful. Never add arbitrary endpoint configuration or a test
that downloads a package distribution.

## Change contract

- Keep schemas explicit and reject unknown fields.
- Preserve missing, empty, unavailable, unsupported, failed, and malformed
  values where their distinction matters.
- Do not generate negative/removal events from incomplete source data.
- Stable event identity must not depend on dictionary or source response order.
- Escape untrusted text and never place it in `innerHTML`.
- Keep GitHub workflow permissions minimal and pin Actions to full commit SHAs.
- Do not add accounts, telemetry, analytics, secrets, or outbound notifications.
- Use neutral review language; do not describe packages as safe, malicious,
  compromised, or trustworthy.

## Pull requests

Explain the observed problem, security/privacy impact, tests added, and commands
run. Keep changes focused. By contributing, you agree that your contribution is
licensed under the repository's MIT License.
