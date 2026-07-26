"""Corruption-aware, locked, deterministic, atomic state persistence."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Final, Self

from pydantic import ValidationError

from distwitness.models import ChangeEvent, SourceHealthObservation, StateDocument

STATE_FILENAME = "state.json"
LOCK_FILENAME = ".lock"
LEGACY_STATE_SCHEMA_VERSION: Final = 1
PHASE_TWO_STATE_SCHEMA_VERSION: Final = 2
CURRENT_STATE_SCHEMA_VERSION: Final = 3
MAX_HEALTH_RUNS: Final = 1_000


class StateError(RuntimeError):
    """Raised when saved state cannot be trusted or safely written."""


class _StateMigrationError(ValueError):
    """Raised when a state version has no explicit migration path."""


class StateLock:
    """Advisory local writer lock for the complete load/compare/save transaction."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self._handle: IO[str] | None = None

    def __enter__(self) -> Self:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_dir / LOCK_FILENAME
        self._handle = lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._handle.close()
            self._handle = None
            raise StateError(
                f"another DistWitness process holds the state lock: {lock_path}"
            ) from exc
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None


def load_state(state_dir: Path) -> StateDocument:
    """Load validated state; never replace or reset a malformed file."""

    path = state_dir / STATE_FILENAME
    if not path.exists():
        return StateDocument()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StateError(f"could not read saved state: {path}") from exc
    try:
        data: Any = json.loads(raw)
        migrated = _migrate_state(data)
        return StateDocument.model_validate(migrated)
    except (json.JSONDecodeError, ValidationError, _StateMigrationError) as exc:
        raise StateError(
            f"saved state is malformed or unsupported; preserved at {path}. "
            "Restore a known-good copy or move it aside after review."
        ) from exc


def save_state_atomic(state_dir: Path, state: StateDocument) -> Path:
    """Write deterministic JSON through an fsynced unpredictable temporary file."""

    state_dir.mkdir(parents=True, exist_ok=True)
    target = state_dir / STATE_FILENAME
    payload = (
        json.dumps(
            state.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    )
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=".state-", dir=state_dir)
        temporary = Path(raw_path)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
        temporary = None
        directory_fd = os.open(state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return target
    except OSError as exc:
        raise StateError(f"could not atomically write saved state: {target}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prune_events(
    events: tuple[ChangeEvent, ...],
    *,
    now: datetime,
    retention_days: int,
) -> tuple[ChangeEvent, ...]:
    """Prune by UTC detection time, deduplicate by ID, and order newest first."""

    cutoff = now - timedelta(days=retention_days)
    by_id: dict[str, ChangeEvent] = {}
    for event in events:
        if event.detected_at >= cutoff:
            existing = by_id.get(event.id)
            if existing is None or event.detected_at > existing.detected_at:
                by_id[event.id] = event
    return tuple(
        sorted(
            by_id.values(),
            key=lambda item: (item.detected_at, item.id),
            reverse=True,
        )
    )


def prune_health_observations(
    observations: tuple[SourceHealthObservation, ...],
    *,
    now: datetime,
    retention_days: int,
) -> tuple[SourceHealthObservation, ...]:
    """Retain bounded complete run groups, newest first."""

    cutoff = now - timedelta(days=retention_days)
    by_key: dict[tuple[str, datetime], SourceHealthObservation] = {}
    for observation in observations:
        if observation.observed_at >= cutoff:
            by_key[(observation.source, observation.observed_at)] = observation
    retained_runs = set(
        sorted(
            {observed_at for _, observed_at in by_key},
            reverse=True,
        )[:MAX_HEALTH_RUNS]
    )
    return tuple(
        sorted(
            (
                observation
                for observation in by_key.values()
                if observation.observed_at in retained_runs
            ),
            key=lambda item: (item.observed_at, item.source),
            reverse=True,
        )
    )


def _migrate_state(data: Any) -> Any:
    """Migrate known historical state in memory without rewriting the source file."""

    if not isinstance(data, dict):
        return data
    migrated = deepcopy(data)
    version = migrated.get("schema_version")
    if version == CURRENT_STATE_SCHEMA_VERSION:
        return migrated
    if version not in {
        LEGACY_STATE_SCHEMA_VERSION,
        PHASE_TWO_STATE_SCHEMA_VERSION,
    }:
        raise _StateMigrationError(f"unsupported state schema version: {version}")

    if version == LEGACY_STATE_SCHEMA_VERSION:
        snapshots = migrated.get("snapshots")
        if not isinstance(snapshots, dict):
            raise _StateMigrationError("legacy state snapshots are malformed")
        for snapshot in snapshots.values():
            if (
                not isinstance(snapshot, dict)
                or snapshot.get("schema_version") != LEGACY_STATE_SCHEMA_VERSION
            ):
                raise _StateMigrationError(
                    "legacy state contains a mixed or malformed snapshot schema"
                )
            snapshot["schema_version"] = PHASE_TWO_STATE_SCHEMA_VERSION
            snapshot["release_discovery"] = "legacy-project-json"
            snapshot["index_api_version"] = None

    migrated["source_health_history"] = []
    migrated["schema_version"] = CURRENT_STATE_SCHEMA_VERSION
    return migrated
