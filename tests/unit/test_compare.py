from __future__ import annotations

from datetime import timedelta

from distwitness.compare import compare_snapshots
from distwitness.models import (
    ChangeEvent,
    PackageConfig,
    PackageSnapshot,
    ProjectConfig,
    ProvenanceState,
    ReviewPriority,
)
from tests.factories import NOW, release_file, snapshot, source_error, vulnerability

PACKAGE_CONFIG = PackageConfig(name="demo")
PROJECT_CONFIG = ProjectConfig(
    title="Test",
    file_size_change_percent=40,
    file_size_change_min_bytes=100_000,
)


def _compare(old: PackageSnapshot, new: PackageSnapshot) -> dict[str, ChangeEvent]:
    events = compare_snapshots(
        old,
        new,
        package_config=PACKAGE_CONFIG,
        project_config=PROJECT_CONFIG,
        detected_at=NOW,
    )
    return {event.event_type: event for event in events}


def test_first_observation_is_a_baseline_without_events() -> None:
    assert not compare_snapshots(
        None,
        snapshot(),
        package_config=PACKAGE_CONFIG,
        project_config=PROJECT_CONFIG,
        detected_at=NOW,
    )


def test_collector_migration_does_not_create_a_package_change_event() -> None:
    old = snapshot().model_copy(
        update={
            "release_discovery": "legacy-project-json",
            "index_api_version": None,
        }
    )
    assert not _compare(old, snapshot())


def test_new_release_and_all_yanked_changes() -> None:
    new_file = release_file(filename="demo-2.0.0-py3-none-any.whl", yanked=True)
    events = _compare(snapshot(), snapshot(version="2.0.0", files=(new_file,)))
    assert events["new_release"].review_priority == ReviewPriority.INFORMATIONAL
    assert events["release_yanked_changed"].review_priority == ReviewPriority.URGENT
    assert "distribution_file_added" not in events
    assert "distribution_file_removed" not in events


def test_distribution_file_set_changes_are_compared_within_one_release() -> None:
    old_file = release_file(filename="demo-1.0.0-old.whl")
    new_file = release_file(filename="demo-1.0.0-new.whl")

    events = _compare(
        snapshot(files=(old_file,)),
        snapshot(files=(new_file,)),
    )

    assert events["distribution_file_added"].new_value == new_file.filename
    assert events["distribution_file_removed"].old_value == old_file.filename


def test_same_filename_digest_and_immutable_metadata_changes_are_urgent() -> None:
    changed = release_file(
        sha256="b" * 64,
        package_type="sdist",
    )
    events = _compare(snapshot(), snapshot(files=(changed,)))
    assert (
        events["distribution_digest_changed"].review_priority == ReviewPriority.URGENT
    )
    assert "distribution_immutable_metadata_changed" in events


def test_size_change_requires_percent_and_absolute_threshold() -> None:
    assert "distribution_size_changed" not in _compare(
        snapshot(files=(release_file(size=10_000),)),
        snapshot(files=(release_file(size=15_000),)),
    )
    events = _compare(
        snapshot(files=(release_file(size=200_000),)),
        snapshot(files=(release_file(size=400_000),)),
    )
    assert events["distribution_size_changed"].evidence["delta_bytes"] == 200_000


def test_dependency_license_python_and_url_changes_are_detected() -> None:
    old = snapshot()
    new = snapshot(
        requires_python=">=3.13",
        requires_dist=("httpx>=0.29", "packaging>=25"),
        license_expression="Apache-2.0",
        project_urls={"Source": "https://example.test/new/"},
    )
    events = _compare(old, new)
    assert {
        "requires_python_changed",
        "dependencies_changed",
        "license_expression_changed",
        "project_urls_changed",
    } <= set(events)
    assert events["dependencies_changed"].evidence["added"]


def test_provenance_present_absent_and_publisher_changes() -> None:
    old = snapshot(
        files=(
            release_file(
                provenance_state=ProvenanceState.PRESENT,
                publishers=("GitHub / old",),
            ),
        )
    )
    absent = snapshot(files=(release_file(provenance_state=ProvenanceState.ABSENT),))
    assert (
        _compare(old, absent)["provenance_state_changed"].review_priority
        == ReviewPriority.REVIEW
    )
    changed_publisher = snapshot(
        files=(
            release_file(
                provenance_state=ProvenanceState.PRESENT,
                publishers=("GitHub / new",),
            ),
        )
    )
    assert "provenance_publisher_changed" in _compare(old, changed_publisher)


def test_unavailable_provenance_does_not_become_disappearance() -> None:
    old = snapshot(files=(release_file(provenance_state=ProvenanceState.PRESENT),))
    unavailable = snapshot(
        files=(release_file(provenance_state=ProvenanceState.REQUEST_FAILED),)
    )
    assert "provenance_state_changed" not in _compare(old, unavailable)


def test_advisory_addition_and_removal_priorities() -> None:
    added = _compare(
        snapshot(),
        snapshot(vulnerabilities=(vulnerability(severity_label="high"),)),
    )
    assert added["advisory_added"].review_priority == ReviewPriority.URGENT
    removed = _compare(
        snapshot(vulnerabilities=(vulnerability(),)),
        snapshot(),
    )
    assert removed["advisory_removed"].review_priority == ReviewPriority.INFORMATIONAL


def test_osv_error_suppresses_advisory_removal() -> None:
    old = snapshot(vulnerabilities=(vulnerability(),))
    new = snapshot(source_errors=(source_error(),))
    assert "advisory_removed" not in _compare(old, new)


def test_event_identity_ignores_detection_time_and_is_deterministic() -> None:
    old = snapshot()
    new = snapshot(version="1.1.0")
    first = compare_snapshots(
        old,
        new,
        package_config=PACKAGE_CONFIG,
        project_config=PROJECT_CONFIG,
        detected_at=NOW,
    )
    second = compare_snapshots(
        old,
        new,
        package_config=PACKAGE_CONFIG,
        project_config=PROJECT_CONFIG,
        detected_at=NOW + timedelta(days=1),
    )
    assert [event.id for event in first] == [event.id for event in second]
    assert [event.event_type for event in first] == sorted(
        event.event_type for event in first
    )
