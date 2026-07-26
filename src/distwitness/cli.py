"""Command-line interface for validation, collection, builds, and diagnostics."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Annotated

import typer

from distwitness import __version__
from distwitness.config import ConfigError, load_config
from distwitness.logging import configure_logging
from distwitness.render import RenderError, build_site
from distwitness.runner import RunOutcome, collect, prepare_run
from distwitness.storage import StateError, StateLock, load_state

app = typer.Typer(
    name="distwitness",
    help="Deterministic review signals for Python package release metadata.",
    no_args_is_help=True,
    add_completion=False,
)

ConfigPath = Annotated[
    Path,
    typer.Option(
        "--config",
        help="Path to the strict YAML watchlist.",
        dir_okay=False,
        resolve_path=True,
    ),
]
StateDir = Annotated[
    Path,
    typer.Option(
        "--state-dir",
        help="Directory for compact versioned state.",
        file_okay=False,
        resolve_path=True,
    ),
]
OutputDir = Annotated[
    Path,
    typer.Option(
        "--output-dir",
        help="Directory for generated static files.",
        file_okay=False,
        resolve_path=True,
    ),
]
Verbose = Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logs.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"distwitness {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed version.",
        ),
    ] = False,
) -> None:
    """Observe metadata changes without downloading or executing packages."""


@app.command()
def validate(
    config: ConfigPath = Path("config/watchlist.yml"),
    state_dir: StateDir = Path("state"),
    verbose: Verbose = False,
) -> None:
    """Validate configuration and any existing saved state."""

    configure_logging(verbose=verbose)
    try:
        watchlist = load_config(config)
        with StateLock(state_dir):
            state = load_state(state_dir)
    except (ConfigError, StateError) as exc:
        _fail(str(exc), code=2 if isinstance(exc, ConfigError) else 4)
    typer.echo(
        f"Valid configuration: {len(watchlist.packages)} package(s), "
        f"{len(state.snapshots)} saved snapshot(s), {len(state.events)} event(s)."
    )


@app.command()
def scan(
    config: ConfigPath = Path("config/watchlist.yml"),
    state_dir: StateDir = Path("state"),
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Disable in-process conditional caching.")
    ] = False,
    verbose: Verbose = False,
) -> None:
    """Fetch and normalise current remote data without persisting it."""

    configure_logging(verbose=verbose)
    try:
        watchlist = load_config(config)
        with StateLock(state_dir):
            previous = load_state(state_dir)
        result = collect(
            watchlist,
            previous=previous,
            no_cache=no_cache,
        )
    except (ConfigError, StateError) as exc:
        _fail(str(exc), code=2 if isinstance(exc, ConfigError) else 4)
    for name in result.successful_packages:
        snapshot = result.snapshots[name]
        typer.echo(
            f"{name}: {snapshot.release.version}; "
            f"{len(snapshot.release.files)} file(s); "
            f"{len(snapshot.vulnerabilities)} advisory record(s)"
        )
    typer.echo(
        f"Scan complete: {len(result.successful_packages)} succeeded, "
        f"{len(result.failed_packages)} failed, "
        f"{len(result.source_errors)} source problem(s). No state was written."
    )
    if not result.successful_packages:
        raise typer.Exit(code=3)


@app.command()
def build(
    config: ConfigPath = Path("config/watchlist.yml"),
    state_dir: StateDir = Path("state"),
    output_dir: OutputDir = Path("site-output"),
    verbose: Verbose = False,
) -> None:
    """Generate all static outputs from existing state without network access."""

    configure_logging(verbose=verbose)
    try:
        watchlist = load_config(config)
        with StateLock(state_dir):
            state = load_state(state_dir)
        written = build_site(state, watchlist, output_dir=output_dir)
    except (ConfigError, StateError, RenderError) as exc:
        _fail(str(exc), code=2 if isinstance(exc, ConfigError) else 4)
    typer.echo(f"Built {len(written)} static file(s) in {output_dir}.")


@app.command()
def run(  # noqa: PLR0917 - Typer exposes each CLI option as a parameter.
    config: ConfigPath = Path("config/watchlist.yml"),
    state_dir: StateDir = Path("state"),
    output_dir: OutputDir = Path("site-output"),
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Collect and compare without writing state or generated output.",
        ),
    ] = False,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Disable in-process conditional caching.")
    ] = False,
    verbose: Verbose = False,
) -> None:
    """Perform collection, comparison, persistence, and static generation."""

    configure_logging(verbose=verbose)
    try:
        outcome = prepare_run(
            config_path=config,
            state_dir=state_dir,
            output_dir=output_dir,
            dry_run=dry_run,
            no_cache=no_cache,
        )
    except ConfigError as exc:
        _fail(str(exc), code=2)
    except StateError as exc:
        _fail(str(exc), code=4)
    except (RenderError, OSError) as exc:
        _fail(str(exc), code=3)
    result = outcome.result
    summary = (
        f"Run complete: {len(result.successful_packages)} package(s) updated, "
        f"{len(result.failed_packages)} failed, {result.events_created} new event(s), "
        f"{len(result.source_errors)} source problem(s)"
    )
    if dry_run:
        summary += "; dry run wrote no state or output"
    else:
        summary += f"; output: {output_dir}"
    typer.echo(summary + ".")
    _append_job_summary(outcome)
    if outcome.operational_failure:
        raise typer.Exit(code=3)


@app.command()
def doctor(
    config: ConfigPath = Path("config/watchlist.yml"),
    state_dir: StateDir = Path("state"),
    output_dir: OutputDir = Path("site-output"),
    verbose: Verbose = False,
) -> None:
    """Report environment, configuration, and state readiness without secret data."""

    configure_logging(verbose=verbose)
    problems: list[str] = []
    typer.echo(f"DistWitness: {__version__}")
    typer.echo(f"Python: {platform.python_version()} ({sys.executable})")
    try:
        watchlist = load_config(config)
        typer.echo(f"Configuration: valid ({len(watchlist.packages)} packages)")
    except ConfigError as exc:
        problems.append(str(exc))
        typer.echo("Configuration: invalid")
    try:
        with StateLock(state_dir):
            state = load_state(state_dir)
        typer.echo(
            f"State: valid ({len(state.snapshots)} snapshots, "
            f"{len(state.events)} events)"
        )
    except StateError as exc:
        problems.append(str(exc))
        typer.echo("State: invalid or locked")
    for label, path in (
        ("state parent", state_dir.parent),
        ("output parent", output_dir.parent),
    ):
        if not path.exists():
            typer.echo(f"{label}: will be created")
        elif os.access(path, os.W_OK):
            typer.echo(f"{label}: writable")
        else:
            problems.append(f"{label} is not writable: {path}")
    if problems:
        typer.echo("Problems:")
        for problem in problems:
            typer.echo(f"- {problem}")
        raise typer.Exit(code=3)
    typer.echo("Doctor found no blocking local problems.")


def _append_job_summary(outcome: RunOutcome) -> None:
    path_value = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path_value:
        return
    path = Path(path_value)
    result = outcome.result
    lines = [
        "## DistWitness run",
        "",
        f"- Packages updated: {len(result.successful_packages)}",
        f"- Package failures: {len(result.failed_packages)}",
        f"- New change events: {result.events_created}",
        f"- Source problems: {len(result.source_errors)}",
        "",
    ]
    latest_health = tuple(
        sorted(
            (
                observation
                for observation in outcome.state.source_health_history
                if observation.observed_at == result.completed_at
            ),
            key=lambda item: item.source,
        )
    )
    if latest_health:
        lines.extend(["### Source observations", ""])
        lines.extend(
            (
                f"- {observation.source.replace('_', ' ')}: "
                f"{observation.status.replace('_', ' ')}; "
                f"{observation.successful_packages} of "
                f"{observation.checked_packages} package checks without "
                "recorded source errors"
            )
            for observation in latest_health
        )
        lines.append("")
    lines.extend(
        [
            "Findings are review signals, not verdicts about package safety or intent.",
            "",
        ]
    )
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    except OSError:
        typer.echo("Warning: could not append the GitHub Actions job summary.")


def _fail(message: str, *, code: int) -> None:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=code)
