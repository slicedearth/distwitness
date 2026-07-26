"""Application orchestration with partial-source and persistence safeguards."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from distwitness.compare import compare_snapshots
from distwitness.config import load_config
from distwitness.http import BoundedHttpClient, SourceRequestError
from distwitness.models import (
    ChangeEvent,
    PackageSnapshot,
    RunResult,
    SourceError,
    SourceHealthObservation,
    SourceHealthStatus,
    SourceName,
    StateDocument,
    WatchlistConfig,
)
from distwitness.osv import OsvClient
from distwitness.pypi import PackageDataError, PyPIClient
from distwitness.render import build_site
from distwitness.storage import (
    StateLock,
    load_state,
    prune_events,
    prune_health_observations,
    save_state_atomic,
)


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Current snapshots and source health from one remote collection."""

    snapshots: dict[str, PackageSnapshot]
    successful_packages: tuple[str, ...]
    failed_packages: tuple[str, ...]
    source_errors: tuple[SourceError, ...]


@dataclass(frozen=True, slots=True)
class RunOutcome:
    """State ready for rendering plus whether an operational failure occurred."""

    state: StateDocument
    result: RunResult
    operational_failure: bool


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(UTC)


def collect(
    config: WatchlistConfig,
    *,
    previous: StateDocument | None = None,
    no_cache: bool = False,
    now: datetime | None = None,
    http: BoundedHttpClient | None = None,
) -> CollectionResult:
    """Collect PyPI and OSV data while preserving partial-source distinctions."""

    observed_at = now or utc_now()
    previous_snapshots = previous.snapshots if previous else {}
    snapshots: dict[str, PackageSnapshot] = {}
    errors: list[SourceError] = []
    failed: list[str] = []
    owns_http = http is None
    bounded_http = http or BoundedHttpClient(
        user_agent=config.project.user_agent,
        no_cache=no_cache,
    )
    try:
        pypi = PyPIClient(bounded_http)
        for package in config.packages:
            name = package.normalised_name
            include_prereleases = (
                package.include_prereleases
                if package.include_prereleases is not None
                else config.project.include_prereleases_by_default
            )
            try:
                snapshot = pypi.fetch_package(
                    package,
                    include_prereleases=include_prereleases,
                    observed_at=observed_at,
                )
                snapshots[name] = snapshot
                errors.extend(snapshot.source_errors)
            except (PackageDataError, SourceRequestError) as exc:
                failed.append(name)
                errors.append(
                    SourceError(
                        source="pypi",
                        package_name=name,
                        code=getattr(exc, "code", "malformed_response")[:80],
                        message=str(exc)[:2000],
                        occurred_at=observed_at,
                        retryable=getattr(exc, "retryable", False),
                        source_url=getattr(
                            exc,
                            "url",
                            f"https://pypi.org/simple/{name}/",
                        ),
                    )
                )

        if snapshots:
            osv = OsvClient(bounded_http).query_packages(
                snapshots, observed_at=observed_at
            )
            errors.extend(osv.errors)
            errors_by_package: dict[str, list[SourceError]] = {}
            for error in osv.errors:
                if error.package_name:
                    errors_by_package.setdefault(error.package_name, []).append(error)
            for name, snapshot in list(snapshots.items()):
                package_errors = errors_by_package.get(name, [])
                vulnerabilities = osv.vulnerabilities.get(name, ())
                if name in osv.incomplete_packages:
                    old = previous_snapshots.get(name)
                    if old and old.release.version == snapshot.release.version:
                        vulnerabilities = old.vulnerabilities
                snapshots[name] = snapshot.model_copy(
                    update={
                        "vulnerabilities": vulnerabilities,
                        "source_errors": tuple(
                            sorted(
                                (*snapshot.source_errors, *package_errors),
                                key=lambda item: (
                                    item.source,
                                    item.code,
                                    item.source_url or "",
                                ),
                            )
                        ),
                    }
                )
    finally:
        if owns_http:
            bounded_http.close()
    return CollectionResult(
        snapshots=snapshots,
        successful_packages=tuple(sorted(snapshots)),
        failed_packages=tuple(sorted(failed)),
        source_errors=tuple(
            sorted(
                errors,
                key=lambda item: (
                    item.package_name or "",
                    item.source,
                    item.code,
                    item.source_url or "",
                ),
            )
        ),
    )


def build_source_health_observations(
    config: WatchlistConfig,
    collected: CollectionResult,
    *,
    observed_at: datetime,
) -> tuple[SourceHealthObservation, ...]:
    """Summarise source completeness without inventing request-level precision."""

    configured_names = {package.normalised_name for package in config.packages}
    collected_names = set(collected.successful_packages)
    observations: list[SourceHealthObservation] = []
    sources: tuple[SourceName, ...] = ("pypi", "pypi_integrity", "osv")
    for source in sources:
        source_errors = tuple(
            error for error in collected.source_errors if error.source == source
        )
        checked_names = configured_names if source == "pypi" else collected_names
        checked_packages = len(checked_names)
        status: SourceHealthStatus
        if checked_packages == 0:
            status = "not_checked"
            successful_packages = 0
        else:
            errors_without_package = any(
                error.package_name is None for error in source_errors
            )
            failed_names = {
                error.package_name
                for error in source_errors
                if error.package_name in checked_names
            }
            successful_packages = (
                0 if errors_without_package else checked_packages - len(failed_names)
            )
            if not source_errors and successful_packages == checked_packages:
                status = "available"
            elif any(not error.retryable for error in source_errors):
                status = "degraded"
            else:
                status = "partial"
        observations.append(
            SourceHealthObservation(
                source=source,
                observed_at=observed_at,
                status=status,
                checked_packages=checked_packages,
                successful_packages=successful_packages,
                error_count=len(source_errors),
                retryable_error_count=sum(
                    1 for error in source_errors if error.retryable
                ),
            )
        )
    return tuple(observations)


def prepare_run(
    *,
    config_path: Path,
    state_dir: Path,
    output_dir: Path | None = None,
    dry_run: bool,
    no_cache: bool,
    now: datetime | None = None,
    http: BoundedHttpClient | None = None,
) -> RunOutcome:
    """Collect, compare, deduplicate, and prepare a state transaction."""

    started_at = now or utc_now()
    config = load_config(config_path)
    with StateLock(state_dir):
        previous = load_state(state_dir)
        collected = collect(
            config,
            previous=previous,
            no_cache=no_cache,
            now=started_at,
            http=http,
        )
        configured_names = {package.normalised_name for package in config.packages}
        snapshots = {
            name: snapshot
            for name, snapshot in previous.snapshots.items()
            if name in configured_names
        }
        snapshots.update(collected.snapshots)
        new_events: list[ChangeEvent] = []
        configs = {item.normalised_name: item for item in config.packages}
        for name in collected.successful_packages:
            new_events.extend(
                compare_snapshots(
                    previous.snapshots.get(name),
                    collected.snapshots[name],
                    package_config=configs[name],
                    project_config=config.project,
                    detected_at=started_at,
                )
            )
        existing_ids = {event.id for event in previous.events}
        unique_new = tuple(
            event for event in new_events if event.id not in existing_ids
        )
        events = prune_events(
            (*previous.events, *unique_new),
            now=started_at,
            retention_days=config.project.retention_days,
        )
        completed_at = utc_now() if now is None else now
        operational_failure = not bool(collected.successful_packages)
        output_built = (
            not dry_run and not operational_failure and output_dir is not None
        )
        run_result = RunResult(
            started_at=started_at,
            completed_at=completed_at,
            successful_packages=collected.successful_packages,
            failed_packages=collected.failed_packages,
            events_created=len(unique_new),
            source_errors=collected.source_errors,
            output_built=output_built,
            dry_run=dry_run,
        )
        source_health_history = prune_health_observations(
            (
                *previous.source_health_history,
                *build_source_health_observations(
                    config,
                    collected,
                    observed_at=completed_at,
                ),
            ),
            now=completed_at,
            retention_days=config.project.retention_days,
        )
        fully_successful = not collected.failed_packages and not collected.source_errors
        state = StateDocument(
            snapshots=dict(sorted(snapshots.items())),
            events=events,
            source_health_history=source_health_history,
            last_run=run_result,
            last_successful_run=(
                completed_at if fully_successful else previous.last_successful_run
            ),
        )
        if output_built and output_dir is not None:
            build_site(state, config, output_dir=output_dir)
        if not dry_run and not operational_failure:
            save_state_atomic(state_dir, state)
        return RunOutcome(
            state=state,
            result=run_result,
            operational_failure=operational_failure,
        )
