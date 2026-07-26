"""Deterministic comparisons that produce review signals, never verdicts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from distwitness.models import (
    ChangeEvent,
    DataConfidence,
    PackageConfig,
    PackageSnapshot,
    ProjectConfig,
    ProvenanceState,
    ReviewPriority,
)

_INCOMPLETE_PROVENANCE = {
    ProvenanceState.UNAVAILABLE,
    ProvenanceState.REQUEST_FAILED,
    ProvenanceState.MALFORMED_RESPONSE,
    ProvenanceState.UNSUPPORTED,
}


def compare_snapshots(
    old: PackageSnapshot | None,
    new: PackageSnapshot,
    *,
    package_config: PackageConfig,
    project_config: ProjectConfig,
    detected_at: datetime,
) -> tuple[ChangeEvent, ...]:
    """Return stable, ordered events for one complete old/new observation pair."""

    if old is None:
        return ()
    events: list[ChangeEvent] = []
    release_link = new.release.source_url

    if old.release.version != new.release.version:
        events.append(
            _event(
                event_type="new_release",
                package_name=new.name,
                old_value=old.release.version,
                new_value=new.release.version,
                detected_at=detected_at,
                source_timestamp=new.release.source_timestamp,
                priority=ReviewPriority.INFORMATIONAL,
                explanation=(
                    f"Selected stable release changed from {old.release.version} "
                    f"to {new.release.version}. Review recommended in the context "
                    "of your own dependency policy."
                ),
                source_links=(release_link,),
                evidence={"selection_policy": "highest eligible PEP 440 release"},
            )
        )

    if old.release.yanked != new.release.yanked:
        became_yanked = new.release.yanked
        events.append(
            _event(
                event_type="release_yanked_changed",
                package_name=new.name,
                old_value=old.release.yanked,
                new_value=new.release.yanked,
                detected_at=detected_at,
                source_timestamp=new.release.source_timestamp,
                priority=(
                    ReviewPriority.URGENT
                    if became_yanked
                    else ReviewPriority.INFORMATIONAL
                ),
                explanation=(
                    "The selected release is now reported as fully yanked by PyPI; "
                    "prompt review is recommended."
                    if became_yanked
                    else "The selected release is no longer reported as fully yanked."
                ),
                source_links=(release_link,),
                evidence={"all_files_yanked": new.release.all_files_yanked},
            )
        )

    old_files = {item.filename: item for item in old.release.files}
    new_files = {item.filename: item for item in new.release.files}
    for filename in sorted(new_files.keys() - old_files.keys()):
        item = new_files[filename]
        events.append(
            _event(
                event_type="distribution_file_added",
                package_name=new.name,
                old_value=None,
                new_value=filename,
                detected_at=detected_at,
                source_timestamp=item.upload_time,
                priority=ReviewPriority.INFORMATIONAL,
                explanation=(
                    f"PyPI now reports an additional distribution file: {filename}."
                ),
                source_links=(release_link,),
                evidence={
                    "filename": filename,
                    "sha256": item.sha256,
                    "package_type": item.package_type,
                },
            )
        )
    for filename in sorted(old_files.keys() - new_files.keys()):
        item = old_files[filename]
        events.append(
            _event(
                event_type="distribution_file_removed",
                package_name=new.name,
                old_value=filename,
                new_value=None,
                detected_at=detected_at,
                source_timestamp=new.release.source_timestamp,
                priority=ReviewPriority.REVIEW,
                explanation=f"PyPI no longer reports distribution file {filename}.",
                source_links=(release_link,),
                evidence={"filename": filename, "previous_sha256": item.sha256},
            )
        )

    percent_threshold = (
        package_config.file_size_change_percent
        or project_config.file_size_change_percent
    )
    byte_threshold = (
        package_config.file_size_change_min_bytes
        if package_config.file_size_change_min_bytes is not None
        else project_config.file_size_change_min_bytes
    )
    for filename in sorted(old_files.keys() & new_files.keys()):
        old_file = old_files[filename]
        new_file = new_files[filename]
        links = (new_file.provenance.source_url, release_link)
        if old_file.sha256 != new_file.sha256:
            events.append(
                _event(
                    event_type="distribution_digest_changed",
                    package_name=new.name,
                    old_value=old_file.sha256,
                    new_value=new_file.sha256,
                    detected_at=detected_at,
                    source_timestamp=new_file.upload_time,
                    priority=ReviewPriority.URGENT,
                    explanation=(
                        f"The SHA-256 digest reported for existing file {filename} "
                        "changed. Prompt review of the authoritative record is "
                        "recommended."
                    ),
                    source_links=links,
                    evidence={"filename": filename},
                )
            )
        delta = new_file.size - old_file.size
        percent = (
            (abs(delta) / old_file.size) * 100
            if old_file.size
            else (100.0 if new_file.size else 0.0)
        )
        if abs(delta) >= byte_threshold and percent >= percent_threshold:
            events.append(
                _event(
                    event_type="distribution_size_changed",
                    package_name=new.name,
                    old_value=old_file.size,
                    new_value=new_file.size,
                    detected_at=detected_at,
                    source_timestamp=new_file.upload_time,
                    priority=ReviewPriority.REVIEW,
                    explanation=(
                        f"Reported size for {filename} changed by {delta:+d} bytes "
                        f"({percent:.1f}%), meeting the configured review threshold."
                    ),
                    source_links=(release_link,),
                    evidence={
                        "filename": filename,
                        "delta_bytes": delta,
                        "delta_percent": round(percent, 3),
                        "threshold_percent": percent_threshold,
                        "threshold_min_bytes": byte_threshold,
                    },
                )
            )
        immutable_old = {
            "package_type": old_file.package_type,
            "upload_time": _json_value(old_file.upload_time),
            "python_version": old_file.python_version,
            "python_tags": old_file.python_tags,
        }
        immutable_new = {
            "package_type": new_file.package_type,
            "upload_time": _json_value(new_file.upload_time),
            "python_version": new_file.python_version,
            "python_tags": new_file.python_tags,
        }
        if immutable_old != immutable_new:
            events.append(
                _event(
                    event_type="distribution_immutable_metadata_changed",
                    package_name=new.name,
                    old_value=immutable_old,
                    new_value=immutable_new,
                    detected_at=detected_at,
                    source_timestamp=new_file.upload_time,
                    priority=ReviewPriority.URGENT,
                    explanation=(
                        f"Immutable metadata reported for existing file {filename} "
                        "changed. Prompt review is recommended."
                    ),
                    source_links=(release_link,),
                    evidence={"filename": filename},
                )
            )
        _append_field_change(
            events,
            event_type="distribution_requires_python_changed",
            package_name=new.name,
            old_value=old_file.requires_python,
            new_value=new_file.requires_python,
            detected_at=detected_at,
            priority=ReviewPriority.REVIEW,
            explanation=(f"The requires_python value reported for {filename} changed."),
            links=(release_link,),
            evidence={"filename": filename},
        )
        if old_file.yanked != new_file.yanked:
            events.append(
                _event(
                    event_type="distribution_yanked_changed",
                    package_name=new.name,
                    old_value=old_file.yanked,
                    new_value=new_file.yanked,
                    detected_at=detected_at,
                    source_timestamp=new_file.upload_time,
                    priority=(
                        ReviewPriority.URGENT
                        if new_file.yanked
                        else ReviewPriority.INFORMATIONAL
                    ),
                    explanation=(
                        f"PyPI's yanked state for {filename} changed to "
                        f"{str(new_file.yanked).lower()}."
                    ),
                    source_links=(release_link,),
                    evidence={
                        "filename": filename,
                        "yanked_reason": new_file.yanked_reason,
                    },
                )
            )
        _compare_provenance(
            events,
            package_name=new.name,
            filename=filename,
            old_file=old_file,
            new_file=new_file,
            detected_at=detected_at,
        )

    _append_field_change(
        events,
        event_type="requires_python_changed",
        package_name=new.name,
        old_value=old.requires_python,
        new_value=new.requires_python,
        detected_at=detected_at,
        priority=ReviewPriority.REVIEW,
        explanation="The selected release's supported-Python declaration changed.",
        links=(release_link,),
    )
    _append_field_change(
        events,
        event_type="dependencies_changed",
        package_name=new.name,
        old_value=old.requires_dist,
        new_value=new.requires_dist,
        detected_at=detected_at,
        priority=ReviewPriority.REVIEW,
        explanation=(
            "Declared dependencies were added, removed, or materially changed; "
            "review recommended."
        ),
        links=(release_link,),
        evidence={
            "added": sorted(set(new.requires_dist) - set(old.requires_dist)),
            "removed": sorted(set(old.requires_dist) - set(new.requires_dist)),
        },
    )
    for event_type, old_value, new_value, explanation in (
        (
            "license_expression_changed",
            old.license_expression,
            new.license_expression,
            "The declared SPDX license expression changed.",
        ),
        (
            "declared_license_changed",
            old.declared_license,
            new.declared_license,
            "The package's declared license field changed.",
        ),
        (
            "license_classifiers_changed",
            old.license_classifiers,
            new.license_classifiers,
            "PyPI licensing classifiers changed.",
        ),
        (
            "project_urls_changed",
            old.project_urls,
            new.project_urls,
            "The package's declared project URLs changed.",
        ),
    ):
        _append_field_change(
            events,
            event_type=event_type,
            package_name=new.name,
            old_value=old_value,
            new_value=new_value,
            detected_at=detected_at,
            priority=ReviewPriority.REVIEW,
            explanation=explanation,
            links=(release_link,),
        )

    if not any(error.source == "osv" for error in new.source_errors):
        _compare_vulnerabilities(events, old=old, new=new, detected_at=detected_at)

    return tuple(sorted(events, key=lambda item: (item.event_type, item.id)))


def _compare_provenance(
    events: list[ChangeEvent],
    *,
    package_name: str,
    filename: str,
    old_file: Any,
    new_file: Any,
    detected_at: datetime,
) -> None:
    old_provenance = old_file.provenance
    new_provenance = new_file.provenance
    if new_provenance.state in _INCOMPLETE_PROVENANCE:
        return
    if old_provenance.state != new_provenance.state:
        priority = (
            ReviewPriority.REVIEW
            if old_provenance.state == ProvenanceState.PRESENT
            and new_provenance.state == ProvenanceState.ABSENT
            else ReviewPriority.INFORMATIONAL
        )
        events.append(
            _event(
                event_type="provenance_state_changed",
                package_name=package_name,
                old_value=old_provenance.state,
                new_value=new_provenance.state,
                detected_at=detected_at,
                source_timestamp=new_file.upload_time,
                priority=priority,
                explanation=(
                    f"Reported provenance availability for {filename} changed from "
                    f"{old_provenance.state} to {new_provenance.state}. This is a "
                    "review signal, not a trust verdict."
                ),
                source_links=(new_provenance.source_url,),
                evidence={"filename": filename},
            )
        )
    if (
        old_provenance.state == ProvenanceState.PRESENT
        and new_provenance.state == ProvenanceState.PRESENT
        and old_provenance.publishers != new_provenance.publishers
    ):
        events.append(
            _event(
                event_type="provenance_publisher_changed",
                package_name=package_name,
                old_value=old_provenance.publishers,
                new_value=new_provenance.publishers,
                detected_at=detected_at,
                source_timestamp=new_file.upload_time,
                priority=ReviewPriority.REVIEW,
                explanation=(
                    f"The publisher identity reported by PyPI for {filename} changed."
                ),
                source_links=(new_provenance.source_url,),
                evidence={"filename": filename},
            )
        )


def _compare_vulnerabilities(
    events: list[ChangeEvent],
    *,
    old: PackageSnapshot,
    new: PackageSnapshot,
    detected_at: datetime,
) -> None:
    old_vulns = {item.id: item for item in old.vulnerabilities}
    new_vulns = {item.id: item for item in new.vulnerabilities}
    for advisory_id in sorted(new_vulns.keys() - old_vulns.keys()):
        advisory = new_vulns[advisory_id]
        urgent = advisory.severity_label in {"high", "critical"}
        events.append(
            _event(
                event_type="advisory_added",
                package_name=new.name,
                old_value=None,
                new_value=advisory_id,
                detected_at=detected_at,
                source_timestamp=advisory.modified or advisory.published,
                priority=ReviewPriority.URGENT if urgent else ReviewPriority.REVIEW,
                explanation=(
                    f"OSV reports advisory {advisory_id} as affecting the exact "
                    f"selected version {new.release.version}. Review recommended."
                ),
                source_links=(advisory.source_url,),
                evidence={
                    "aliases": advisory.aliases,
                    "severity_type": advisory.severity_type,
                    "severity_score": advisory.severity_score,
                    "severity_label": advisory.severity_label,
                },
            )
        )
    for advisory_id in sorted(old_vulns.keys() - new_vulns.keys()):
        advisory = old_vulns[advisory_id]
        events.append(
            _event(
                event_type="advisory_removed",
                package_name=new.name,
                old_value=advisory_id,
                new_value=None,
                detected_at=detected_at,
                source_timestamp=None,
                priority=ReviewPriority.INFORMATIONAL,
                explanation=(
                    f"OSV no longer reports advisory {advisory_id} as affecting "
                    f"the exact selected version {new.release.version}."
                ),
                source_links=(advisory.source_url,),
                evidence={"previous_aliases": advisory.aliases},
            )
        )
    for advisory_id in sorted(old_vulns.keys() & new_vulns.keys()):
        old_advisory = old_vulns[advisory_id]
        new_advisory = new_vulns[advisory_id]
        old_value = {
            "aliases": old_advisory.aliases,
            "severity_type": old_advisory.severity_type,
            "severity_score": old_advisory.severity_score,
            "severity_label": old_advisory.severity_label,
        }
        new_value = {
            "aliases": new_advisory.aliases,
            "severity_type": new_advisory.severity_type,
            "severity_score": new_advisory.severity_score,
            "severity_label": new_advisory.severity_label,
        }
        _append_field_change(
            events,
            event_type="advisory_metadata_changed",
            package_name=new.name,
            old_value=old_value,
            new_value=new_value,
            detected_at=detected_at,
            priority=ReviewPriority.REVIEW,
            explanation=f"OSV metadata for advisory {advisory_id} changed.",
            links=(new_advisory.source_url,),
            evidence={"advisory_id": advisory_id},
            source_timestamp=new_advisory.modified,
        )


def _append_field_change(
    events: list[ChangeEvent],
    *,
    event_type: str,
    package_name: str,
    old_value: Any,
    new_value: Any,
    detected_at: datetime,
    priority: ReviewPriority,
    explanation: str,
    links: tuple[str, ...],
    evidence: Mapping[str, Any] | None = None,
    source_timestamp: datetime | None = None,
) -> None:
    if old_value == new_value:
        return
    events.append(
        _event(
            event_type=event_type,
            package_name=package_name,
            old_value=old_value,
            new_value=new_value,
            detected_at=detected_at,
            source_timestamp=source_timestamp,
            priority=priority,
            explanation=explanation,
            source_links=links,
            evidence=dict(evidence or {}),
        )
    )


def _event(
    *,
    event_type: str,
    package_name: str,
    old_value: Any,
    new_value: Any,
    detected_at: datetime,
    source_timestamp: datetime | None,
    priority: ReviewPriority,
    explanation: str,
    source_links: tuple[str, ...],
    evidence: Mapping[str, Any],
) -> ChangeEvent:
    identity = {
        "schema_version": 1,
        "event_type": event_type,
        "package_name": package_name,
        "old_value": _json_value(old_value),
        "new_value": _json_value(new_value),
        "source_timestamp": _json_value(source_timestamp),
        "source_links": sorted(set(source_links)),
        "evidence": _json_value(dict(evidence)),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return ChangeEvent(
        id=hashlib.sha256(encoded).hexdigest(),
        event_type=event_type,
        package_name=package_name,
        old_value=_json_value(old_value),
        new_value=_json_value(new_value),
        detected_at=detected_at,
        source_timestamp=source_timestamp,
        review_priority=priority,
        explanation=explanation,
        source_links=tuple(sorted(set(source_links))),
        evidence=_json_value(dict(evidence)),
        data_confidence=DataConfidence.CONFIRMED,
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _json_value(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
        }
    return value
