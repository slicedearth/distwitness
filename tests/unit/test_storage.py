from __future__ import annotations

import json
import stat
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from distwitness.compare import compare_snapshots
from distwitness.models import (
    ChangeEvent,
    PackageConfig,
    ProjectConfig,
    SourceHealthObservation,
    StateDocument,
)
from distwitness.storage import (
    STATE_FILENAME,
    StateError,
    StateLock,
    load_state,
    prune_events,
    prune_health_observations,
    save_state_atomic,
)
from tests.factories import NOW, release_file, snapshot


def _event() -> ChangeEvent:
    return compare_snapshots(
        snapshot(),
        snapshot(version="1.1.0"),
        package_config=PackageConfig(name="demo"),
        project_config=ProjectConfig(title="Test"),
        detected_at=NOW,
    )[0]


def _health(
    *,
    source: str = "pypi",
    observed_at: datetime = NOW,
) -> SourceHealthObservation:
    return SourceHealthObservation.model_validate(
        {
            "source": source,
            "observed_at": observed_at,
            "status": "available",
            "checked_packages": 1,
            "successful_packages": 1,
            "error_count": 0,
            "retryable_error_count": 0,
        }
    )


def test_atomic_round_trip_is_deterministic_and_private(tmp_path: Path) -> None:
    state = StateDocument(snapshots={"demo": snapshot()})
    path = save_state_atomic(tmp_path, state)
    first = path.read_bytes()
    save_state_atomic(tmp_path, state)
    assert path.read_bytes() == first
    assert load_state(tmp_path) == state
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".state-*"))


def test_missing_state_returns_empty_document(tmp_path: Path) -> None:
    assert load_state(tmp_path) == StateDocument()


def test_v1_state_is_migrated_in_memory_without_rewriting_source(
    tmp_path: Path,
) -> None:
    current = StateDocument(snapshots={"demo": snapshot()}).model_dump(mode="json")
    current["schema_version"] = 1
    current.pop("source_health_history")
    old_snapshot = current["snapshots"]["demo"]
    old_snapshot["schema_version"] = 1
    old_snapshot["release_discovery"] = "pypi-index-v1"
    old_snapshot["index_api_version"] = "9.9"
    original = json.dumps(current, sort_keys=True)
    path = tmp_path / STATE_FILENAME
    path.write_text(original, encoding="utf-8")

    migrated = load_state(tmp_path)

    assert migrated.schema_version == 3
    assert migrated.snapshots["demo"].schema_version == 2
    assert migrated.snapshots["demo"].release_discovery == "legacy-project-json"
    assert migrated.snapshots["demo"].index_api_version is None
    assert migrated.source_health_history == ()
    assert path.read_text(encoding="utf-8") == original


def test_v2_state_adds_empty_health_history_without_rewriting_source(
    tmp_path: Path,
) -> None:
    current = StateDocument(snapshots={"demo": snapshot()}).model_dump(mode="json")
    current["schema_version"] = 2
    current.pop("source_health_history")
    original = json.dumps(current, sort_keys=True)
    path = tmp_path / STATE_FILENAME
    path.write_text(original, encoding="utf-8")

    migrated = load_state(tmp_path)

    assert migrated.schema_version == 3
    assert migrated.snapshots["demo"].schema_version == 2
    assert migrated.source_health_history == ()
    assert path.read_text(encoding="utf-8") == original


def test_v1_state_rejects_mixed_snapshot_versions(tmp_path: Path) -> None:
    mixed = StateDocument(snapshots={"demo": snapshot()}).model_dump(mode="json")
    mixed["schema_version"] = 1
    content = json.dumps(mixed, sort_keys=True)
    path = tmp_path / STATE_FILENAME
    path.write_text(content, encoding="utf-8")

    with pytest.raises(StateError, match="preserved"):
        load_state(tmp_path)

    assert path.read_text(encoding="utf-8") == content


@pytest.mark.parametrize(
    ("release_discovery", "index_api_version"),
    [
        ("pypi-index-v1", None),
        ("legacy-project-json", "1.4"),
    ],
)
def test_v2_state_rejects_inconsistent_discovery_provenance(
    tmp_path: Path,
    release_discovery: str,
    index_api_version: str | None,
) -> None:
    state = StateDocument(snapshots={"demo": snapshot()}).model_dump(mode="json")
    state["snapshots"]["demo"]["release_discovery"] = release_discovery
    state["snapshots"]["demo"]["index_api_version"] = index_api_version
    content = json.dumps(state, sort_keys=True)
    path = tmp_path / STATE_FILENAME
    path.write_text(content, encoding="utf-8")

    with pytest.raises(StateError, match="preserved"):
        load_state(tmp_path)

    assert path.read_text(encoding="utf-8") == content


@pytest.mark.parametrize(
    "content",
    ["{", '{"schema_version": 999, "snapshots": {}, "events": []}'],
)
def test_corrupt_or_unsupported_state_is_preserved(
    tmp_path: Path, content: str
) -> None:
    path = tmp_path / STATE_FILENAME
    path.write_text(content, encoding="utf-8")
    with pytest.raises(StateError, match="preserved"):
        load_state(tmp_path)
    assert path.read_text(encoding="utf-8") == content


def test_state_lock_rejects_concurrent_writer(tmp_path: Path) -> None:
    with (
        StateLock(tmp_path),
        pytest.raises(StateError, match="holds the state lock"),
        StateLock(tmp_path),
    ):
        pass


def test_retention_prunes_and_deduplicates() -> None:
    event = _event()
    recent = event.model_copy(update={"detected_at": NOW})
    old = event.model_copy(update={"detected_at": NOW - timedelta(days=40)})
    pruned = prune_events(
        (old, recent, recent),
        now=NOW,
        retention_days=30,
    )
    assert pruned == (recent,)


def test_retention_removes_legacy_cross_release_file_churn() -> None:
    release_change = _event()
    file_changes = compare_snapshots(
        snapshot(files=(release_file(filename="demo-1.0.0-old.whl"),)),
        snapshot(files=(release_file(filename="demo-1.0.0-new.whl"),)),
        package_config=PackageConfig(name="demo"),
        project_config=ProjectConfig(title="Test"),
        detected_at=NOW,
    )
    assert prune_events(file_changes, now=NOW, retention_days=30) == tuple(
        sorted(
            file_changes,
            key=lambda event: (event.detected_at, event.id),
            reverse=True,
        )
    )

    pruned = prune_events(
        (*file_changes, release_change),
        now=NOW,
        retention_days=30,
    )

    assert pruned == (release_change,)


def test_health_retention_preserves_bounded_complete_run_groups() -> None:
    recent_pypi = _health()
    recent_osv = _health(source="osv")
    old = _health(observed_at=NOW - timedelta(days=40))

    retained = prune_health_observations(
        (old, recent_osv, recent_pypi, recent_pypi),
        now=NOW,
        retention_days=30,
    )

    assert retained == (recent_pypi, recent_osv)


@pytest.mark.parametrize(
    "updates",
    [
        {"successful_packages": 2},
        {"retryable_error_count": 1},
        {"status": "available", "error_count": 1},
        {"status": "not_checked", "checked_packages": 1},
        {
            "status": "partial",
            "successful_packages": 0,
            "error_count": 1,
            "retryable_error_count": 0,
        },
        {
            "status": "degraded",
            "successful_packages": 0,
            "error_count": 1,
            "retryable_error_count": 1,
        },
        {
            "status": "partial",
            "error_count": 1,
            "retryable_error_count": 1,
        },
    ],
)
def test_health_observation_rejects_inconsistent_counts(
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "source": "pypi",
        "observed_at": NOW,
        "status": "available",
        "checked_packages": 1,
        "successful_packages": 1,
        "error_count": 0,
        "retryable_error_count": 0,
    }
    values.update(updates)

    with pytest.raises(ValueError):
        SourceHealthObservation.model_validate(values)


def test_state_rejects_incomplete_or_duplicate_health_run_groups() -> None:
    pypi = _health()
    integrity = _health(source="pypi_integrity")
    osv = _health(source="osv")

    with pytest.raises(ValueError, match="incomplete"):
        StateDocument(source_health_history=(pypi, integrity))
    with pytest.raises(ValueError, match="duplicate"):
        StateDocument(source_health_history=(pypi, pypi, integrity, osv))


def test_state_json_has_sorted_keys(tmp_path: Path) -> None:
    path = save_state_atomic(
        tmp_path,
        StateDocument(snapshots={"zulu": snapshot(), "alpha": snapshot()}),
    )
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert list(parsed["snapshots"]) == ["alpha", "zulu"]
