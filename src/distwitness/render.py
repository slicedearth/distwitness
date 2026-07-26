"""Accessible static dashboard and machine-readable artefact generation."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from distwitness.feed import build_atom_feed
from distwitness.models import ChangeEvent, StateDocument, WatchlistConfig

MANIFEST = ".distwitness-manifest.json"
CURRENT_PUBLIC_SCHEMA_VERSION = 3
EVENTS_PUBLIC_SCHEMA_VERSION = 1
HEALTH_PUBLIC_SCHEMA_VERSION = 1
EVENTS_PER_PAGE = 20
FIRST_INTERIOR_PAGE = 2
MEASURED_HISTORY_MIN_RUNS = 7


class RenderError(RuntimeError):
    """Raised when generated output cannot be written safely."""


def build_site(
    state: StateDocument,
    config: WatchlistConfig,
    *,
    output_dir: Path,
) -> tuple[Path, ...]:
    """Generate the complete inert site and return all written paths."""

    output_dir.mkdir(parents=True, exist_ok=True)
    environment = Environment(
        loader=PackageLoader("distwitness", "templates"),
        autoescape=select_autoescape(("html", "xml")),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["utc"] = _utc_text
    environment.filters["label"] = lambda value: str(value).replace("_", " ")
    generated_at = _generated_at(state)
    packages = tuple(state.snapshots[name] for name in sorted(state.snapshots))
    events = tuple(
        sorted(
            state.events,
            key=lambda item: (item.detected_at, item.id),
            reverse=True,
        )
    )
    status = _status(state)
    health = _source_health(state)
    event_types = tuple(sorted({event.event_type for event in events}))
    event_page_count = max(1, (len(events) + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE)
    common = {
        "title": config.project.title,
        "generated_at": generated_at,
        "last_successful_run": state.last_successful_run,
        "status": status,
        "source_health": health,
        "repository_url": "https://github.com/slicedearth/distwitness",
    }
    outputs: dict[str, str | bytes] = {
        "index.html": environment.get_template("index.html").render(
            **common,
            base_url="",
            page_title="Overview",
            packages=packages,
            events=events[:EVENTS_PER_PAGE],
            event_total=len(events),
            event_types=event_types,
            pagination=_pagination_context(
                current_page=1,
                page_count=event_page_count,
                total_events=len(events),
                from_index=True,
            ),
        ),
        "methodology.html": environment.get_template("methodology.html").render(
            **common,
            base_url="",
            page_title="Methodology",
        ),
        "privacy.html": environment.get_template("privacy.html").render(
            **common,
            base_url="",
            page_title="Privacy",
        ),
        "feed.xml": build_atom_feed(
            events,
            title=config.project.title,
            updated_at=generated_at,
        ),
        "data/current.json": _public_current_json(
            packages=packages,
            generated_at=generated_at,
            title=config.project.title,
            health=health,
        ),
        "data/events.json": _public_events_json(
            events=events,
            generated_at=generated_at,
        ),
        "data/health.json": _public_health_json(
            state=state,
            generated_at=generated_at,
            retention_days=config.project.retention_days,
        ),
        "reports/latest.md": _markdown_digest(
            events=events,
            packages=packages,
            generated_at=generated_at,
            title=config.project.title,
            state=state,
            health=health,
        ),
    }
    for package in packages:
        package_events = tuple(
            event for event in events if event.package_name == package.name
        )
        outputs[f"packages/{package.name}.html"] = environment.get_template(
            "package.html"
        ).render(
            **common,
            base_url="../",
            page_title=package.display_name,
            package=package,
            events=package_events,
        )

    for page in range(2, event_page_count + 1):
        offset = (page - 1) * EVENTS_PER_PAGE
        outputs[f"changes/page-{page}.html"] = environment.get_template(
            "changes.html"
        ).render(
            **common,
            base_url="../",
            page_title=f"Changes page {page}",
            packages=packages,
            events=events[offset : offset + EVENTS_PER_PAGE],
            event_total=len(events),
            event_types=event_types,
            pagination=_pagination_context(
                current_page=page,
                page_count=event_page_count,
                total_events=len(events),
                from_index=False,
            ),
        )

    static_root = files("distwitness").joinpath("static")
    for asset in ("styles.css", "app.js", "logo.svg"):
        outputs[f"assets/{asset}"] = static_root.joinpath(asset).read_bytes()

    previous_paths = _load_manifest(output_dir)
    current_paths = set(outputs)
    written: list[Path] = []
    for relative, content in sorted(outputs.items()):
        destination = _safe_destination(output_dir, relative)
        _atomic_write(destination, content)
        written.append(destination)
    stale = previous_paths - current_paths
    for relative in sorted(stale):
        path = _safe_destination(output_dir, relative)
        if path.is_file() or path.is_symlink():
            path.unlink()
    manifest_content = json.dumps(sorted(current_paths), indent=2) + "\n"
    manifest_path = output_dir / MANIFEST
    _atomic_write(manifest_path, manifest_content)
    written.append(manifest_path)
    _remove_empty_generated_dirs(output_dir)
    return tuple(written)


def _public_current_json(
    *,
    packages: tuple[Any, ...],
    generated_at: datetime,
    title: str,
    health: dict[str, dict[str, Any]],
) -> str:
    payload = {
        "schema_version": CURRENT_PUBLIC_SCHEMA_VERSION,
        "generated_at": _utc_text(generated_at),
        "title": title,
        "source_health": health,
        "packages": [
            package.model_dump(mode="json", exclude={"source_errors"})
            for package in packages
        ],
    }
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _public_events_json(
    *, events: tuple[ChangeEvent, ...], generated_at: datetime
) -> str:
    payload = {
        "schema_version": EVENTS_PUBLIC_SCHEMA_VERSION,
        "generated_at": _utc_text(generated_at),
        "events": [event.model_dump(mode="json") for event in events],
    }
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _public_health_json(
    *,
    state: StateDocument,
    generated_at: datetime,
    retention_days: int,
) -> str:
    observations = tuple(
        sorted(
            state.source_health_history,
            key=lambda item: (item.observed_at, item.source),
            reverse=True,
        )
    )
    payload = {
        "schema_version": HEALTH_PUBLIC_SCHEMA_VERSION,
        "generated_at": _utc_text(generated_at),
        "retention_days": retention_days,
        "observations": [
            observation.model_dump(mode="json") for observation in observations
        ],
    }
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _markdown_digest(
    *,
    events: tuple[ChangeEvent, ...],
    packages: tuple[Any, ...],
    generated_at: datetime,
    title: str,
    state: StateDocument,
    health: dict[str, dict[str, Any]],
) -> str:
    lines = [
        f"# {title} latest digest",
        "",
        f"Generated: {_utc_text(generated_at)}",
        "",
        f"Watched packages: {len(packages)}",
        f"Retained change events: {len(events)}",
        "",
    ]
    lines.extend(["## Source health", ""])
    for source, summary in health.items():
        lines.append(
            f"- **{source.replace('_', ' ')}:** {summary['current_status']}; "
            f"{summary['available_runs']} of {summary['observed_runs']} retained "
            "run observation(s) complete; "
            f"{summary['successful_package_checks']} of "
            f"{summary['checked_package_checks']} package checks completed "
            "without a recorded source error."
        )
    lines.append("")
    if state.last_run and state.last_run.source_errors:
        lines.extend(
            [
                (
                    f"{len(state.last_run.source_errors)} source request or validation "
                    "problem(s) were recorded in the latest run. Existing findings "
                    "were "
                    "retained where fresh data could not be verified."
                ),
                "",
            ]
        )
    lines.extend(["## Recent changes", ""])
    if not events:
        lines.extend(
            [
                (
                    "No retained changes have been detected. A first observation "
                    "establishes a baseline and does not create change events."
                ),
                "",
            ]
        )
    for event in events[:50]:
        lines.extend(
            [
                (
                    f"- **{event.package_name} — "
                    f"{event.event_type.replace('_', ' ')}** "
                    f"({event.review_priority.value}): {event.explanation}"
                )
            ]
        )
    lines.extend(
        [
            "",
            (
                "Findings are review signals derived from public metadata, not "
                "verdicts about package safety, trustworthiness, or intent."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def get_pagination_items(
    current_page: int,
    page_count: int,
    sibling_count: int = 2,
) -> tuple[int | None, ...]:
    """Return first/last anchors and a bounded sibling window with gaps."""

    if (
        isinstance(current_page, bool)
        or isinstance(page_count, bool)
        or not isinstance(current_page, int)
        or not isinstance(page_count, int)
        or page_count < 1
        or current_page < 1
        or current_page > page_count
    ):
        raise ValueError("pagination position is outside the published range")
    if (
        isinstance(sibling_count, bool)
        or not isinstance(sibling_count, int)
        or sibling_count < 0
    ):
        raise ValueError("pagination sibling count must be a non-negative integer")

    full_range_limit = sibling_count * 2 + 5
    if page_count <= full_range_limit:
        return tuple(range(1, page_count + 1))

    interior_window_size = sibling_count * 2 + 1
    window_start = current_page - sibling_count
    window_end = current_page + sibling_count
    if window_start <= FIRST_INTERIOR_PAGE:
        window_start = FIRST_INTERIOR_PAGE
        window_end = window_start + interior_window_size - 1
    elif window_end >= page_count - 1:
        window_end = page_count - 1
        window_start = window_end - interior_window_size + 1

    included_pages = {1, page_count}
    included_pages.update(
        page for page in range(window_start, window_end + 1) if 1 < page < page_count
    )
    items: list[int | None] = []
    previous_page: int | None = None
    for page in sorted(included_pages):
        if previous_page is not None and page - previous_page > 1:
            items.append(None)
        items.append(page)
        previous_page = page
    return tuple(items)


def _pagination_context(
    *,
    current_page: int,
    page_count: int,
    total_events: int,
    from_index: bool,
) -> dict[str, Any]:
    def page_href(page: int) -> str:
        if from_index:
            return "#changes" if page == 1 else f"changes/page-{page}.html#changes"
        return "../index.html#changes" if page == 1 else f"page-{page}.html#changes"

    def items(sibling_count: int) -> tuple[dict[str, Any] | None, ...]:
        return tuple(
            None
            if page is None
            else {
                "number": page,
                "href": page_href(page),
                "current": page == current_page,
            }
            for page in get_pagination_items(
                current_page,
                page_count,
                sibling_count,
            )
        )

    first_event = (current_page - 1) * EVENTS_PER_PAGE + 1 if total_events else 0
    last_event = min(current_page * EVENTS_PER_PAGE, total_events)
    return {
        "current_page": current_page,
        "page_count": page_count,
        "total_events": total_events,
        "first_event": first_event,
        "last_event": last_event,
        "previous_href": page_href(current_page - 1) if current_page > 1 else None,
        "next_href": page_href(current_page + 1) if current_page < page_count else None,
        "desktop_items": items(2),
        "mobile_items": items(1),
    }


def _status(state: StateDocument) -> str:
    if not state.snapshots:
        return "No package baseline is available"
    if state.last_run and state.last_run.source_errors:
        return "Partial source data — retained values remain visible"
    return "Sources complete for the latest run"


def _source_health(state: StateDocument) -> dict[str, dict[str, Any]]:
    sources = ("pypi", "pypi_integrity", "osv")
    summaries: dict[str, dict[str, Any]] = {}
    for source in sources:
        observations = tuple(
            sorted(
                (item for item in state.source_health_history if item.source == source),
                key=lambda item: item.observed_at,
                reverse=True,
            )
        )
        observed_runs = len(observations)
        current_status = (
            observations[0].status
            if observations
            else _latest_source_status(state, source)
        )
        summaries[source] = {
            "current_status": current_status,
            "observed_runs": observed_runs,
            "available_runs": sum(
                1 for item in observations if item.status == "available"
            ),
            "partial_runs": sum(1 for item in observations if item.status == "partial"),
            "degraded_runs": sum(
                1 for item in observations if item.status == "degraded"
            ),
            "not_checked_runs": sum(
                1 for item in observations if item.status == "not_checked"
            ),
            "successful_package_checks": sum(
                item.successful_packages for item in observations
            ),
            "checked_package_checks": sum(
                item.checked_packages for item in observations
            ),
            "window_start": (
                _utc_text(observations[-1].observed_at) if observations else None
            ),
            "window_end": (
                _utc_text(observations[0].observed_at) if observations else None
            ),
            "maturity": (
                "no retained history"
                if observed_runs == 0
                else "baseline"
                if observed_runs < MEASURED_HISTORY_MIN_RUNS
                else "measured history"
            ),
        }
    return summaries


def _latest_source_status(state: StateDocument, source: str) -> str:
    if not state.last_run:
        return "not_checked"
    source_errors = tuple(
        error for error in state.last_run.source_errors if error.source == source
    )
    if not source_errors:
        return "available"
    if any(not error.retryable for error in source_errors):
        return "degraded"
    return "partial"


def _generated_at(state: StateDocument) -> datetime:
    if state.last_run:
        return state.last_run.completed_at
    timestamps = [item.collected_at for item in state.snapshots.values()]
    return max(timestamps, default=datetime(1970, 1, 1, tzinfo=UTC))


def _utc_text(value: datetime | None) -> str:
    if value is None:
        return "not yet available"
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _safe_destination(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise RenderError(f"unsafe generated path: {relative}")
    destination = root.joinpath(*pure.parts)
    root_resolved = root.resolve()
    destination_parent = destination.parent.resolve()
    if (
        destination_parent != root_resolved
        and root_resolved not in destination_parent.parents
    ):
        raise RenderError(f"generated path escapes output directory: {relative}")
    return destination


def _atomic_write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(raw_temp)
    try:
        data = content.encode("utf-8") if isinstance(content, str) else content
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        temporary = Path()
    except OSError as exc:
        raise RenderError(f"could not write generated file: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary != Path():
            temporary.unlink(missing_ok=True)


def _load_manifest(output_dir: Path) -> set[str]:
    path = output_dir / MANIFEST
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(data, list):
        return set()
    return {
        item
        for item in data
        if isinstance(item, str)
        and not PurePosixPath(item).is_absolute()
        and ".." not in PurePosixPath(item).parts
    }


def _remove_empty_generated_dirs(output_dir: Path) -> None:
    for relative in ("packages", "reports", "data", "assets", "changes"):
        path = output_dir / relative
        if path.exists() and path.is_dir() and not any(path.iterdir()):
            path.rmdir()
