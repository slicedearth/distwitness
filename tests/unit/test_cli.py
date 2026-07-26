from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from distwitness.cli import app
from distwitness.models import RunResult, SourceHealthObservation, StateDocument
from distwitness.runner import CollectionResult, RunOutcome
from tests.factories import NOW, snapshot

runner = CliRunner()


def _config(path: Path) -> Path:
    path.write_text(
        ("project:\n  title: CLI Test\n  max_packages: 1\npackages:\n  - name: demo\n"),
        encoding="utf-8",
    )
    return path


def test_version_validate_build_and_doctor(tmp_path: Path) -> None:
    config = _config(tmp_path / "watchlist.yml")
    state = tmp_path / "state"
    output = tmp_path / "site"
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0
    assert "distwitness 0.4.0" in version.stdout

    validated = runner.invoke(
        app,
        ["validate", "--config", str(config), "--state-dir", str(state)],
    )
    assert validated.exit_code == 0
    assert "Valid configuration" in validated.stdout

    built = runner.invoke(
        app,
        [
            "build",
            "--config",
            str(config),
            "--state-dir",
            str(state),
            "--output-dir",
            str(output),
        ],
    )
    assert built.exit_code == 0
    assert (output / "index.html").exists()

    diagnosed = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config),
            "--state-dir",
            str(state),
            "--output-dir",
            str(output),
        ],
    )
    assert diagnosed.exit_code == 0
    assert "no blocking local problems" in diagnosed.stdout


def test_scan_reports_success_without_writing(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    config = _config(tmp_path / "watchlist.yml")

    def fake_collect(*_args: object, **_kwargs: object) -> CollectionResult:
        return CollectionResult(
            snapshots={"demo": snapshot()},
            successful_packages=("demo",),
            failed_packages=(),
            source_errors=(),
        )

    monkeypatch.setattr("distwitness.cli.collect", fake_collect)
    result = runner.invoke(
        app,
        ["scan", "--config", str(config), "--state-dir", str(tmp_path / "state")],
    )
    assert result.exit_code == 0
    assert "No state was written" in result.stdout


def test_run_summary_and_actions_summary(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    config = _config(tmp_path / "watchlist.yml")
    summary = tmp_path / "summary.md"
    run_result = RunResult(
        started_at=NOW,
        completed_at=NOW,
        successful_packages=("demo",),
        failed_packages=(),
        events_created=2,
        output_built=True,
        dry_run=False,
    )

    def fake_prepare(**_kwargs: object) -> RunOutcome:
        health = SourceHealthObservation(
            source="pypi",
            observed_at=NOW,
            status="available",
            checked_packages=1,
            successful_packages=1,
            error_count=0,
            retryable_error_count=0,
        )
        return RunOutcome(
            state=StateDocument(
                source_health_history=(
                    health,
                    health.model_copy(update={"source": "pypi_integrity"}),
                    health.model_copy(update={"source": "osv"}),
                ),
                last_run=run_result,
            ),
            result=run_result,
            operational_failure=False,
        )

    monkeypatch.setattr("distwitness.cli.prepare_run", fake_prepare)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(config),
            "--state-dir",
            str(tmp_path / "state"),
            "--output-dir",
            str(tmp_path / "site"),
        ],
    )
    assert result.exit_code == 0
    assert "2 new event(s)" in result.stdout
    summary_text = summary.read_text()
    assert "pypi: available; 1 of 1 package checks" in summary_text
    assert "Findings are review signals" in summary_text


def test_invalid_config_and_corrupt_state_use_documented_exit_codes(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("packages: []\n", encoding="utf-8")
    config_result = runner.invoke(app, ["validate", "--config", str(invalid)])
    assert config_result.exit_code == 2

    config = _config(tmp_path / "watchlist.yml")
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "state.json").write_text("{", encoding="utf-8")
    state_result = runner.invoke(
        app,
        ["validate", "--config", str(config), "--state-dir", str(state_dir)],
    )
    assert state_result.exit_code == 4
