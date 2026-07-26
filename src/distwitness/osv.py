"""Exact-version OSV batch queries and bounded advisory-detail extraction."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast
from urllib.parse import quote

from distwitness.http import BoundedHttpClient, SourceRequestError
from distwitness.models import (
    PackageSnapshot,
    SourceError,
    VulnerabilityReference,
    VulnerabilitySnapshot,
)
from distwitness.normalise import bounded_text, normalise_string_list, normalise_url

MAX_BATCH = 50
MAX_PAGES = 5
MAX_ADVISORIES = 100
MAX_REFERENCES = 20
MAX_TIMESTAMP_LENGTH = 80
MAX_CVSS_SCORE = 10
SeverityLabel = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class OsvResult:
    """OSV observations plus completeness needed for fail-closed updates."""

    vulnerabilities: dict[str, tuple[VulnerabilitySnapshot, ...]]
    errors: tuple[SourceError, ...]
    incomplete_packages: frozenset[str]


class OsvDataError(ValueError):
    """Raised when an OSV response violates the expected bounded schema."""


class OsvClient:
    """Fixed-purpose client for OSV's public batch and detail endpoints."""

    def __init__(self, http: BoundedHttpClient) -> None:
        self.http = http

    def query_packages(  # noqa: PLR0912, PLR0915 - bounded pagination state machine.
        self,
        snapshots: Mapping[str, PackageSnapshot],
        *,
        observed_at: datetime,
    ) -> OsvResult:
        """Query exact selected versions, preserving batch input ordering."""

        names = sorted(snapshots)
        output: dict[str, list[VulnerabilitySnapshot]] = {name: [] for name in names}
        errors: list[SourceError] = []
        incomplete: set[str] = set()
        detail_count = 0

        for start in range(0, len(names), MAX_BATCH):
            chunk = names[start : start + MAX_BATCH]
            pending = [
                {
                    "name": name,
                    "version": snapshots[name].release.version,
                    "page_token": None,
                }
                for name in chunk
            ]
            for _page in range(MAX_PAGES):
                if not pending:
                    break
                queries = []
                for item in pending:
                    query: dict[str, Any] = {
                        "package": {"ecosystem": "PyPI", "name": item["name"]},
                        "version": item["version"],
                    }
                    if item["page_token"]:
                        query["page_token"] = item["page_token"]
                    queries.append(query)
                try:
                    response = self.http.request_json(
                        "POST",
                        "https://api.osv.dev/v1/querybatch",
                        json_body={"queries": queries},
                        max_response_bytes=4 * 1024 * 1024,
                    )
                    data = _mapping(response.data, "OSV batch response")
                    results = data.get("results")
                    if not isinstance(results, list) or len(results) != len(pending):
                        raise OsvDataError(
                            "OSV batch result count does not match query count"
                        )
                except (SourceRequestError, OsvDataError) as exc:
                    for item in pending:
                        name = str(item["name"])
                        incomplete.add(name)
                        errors.append(
                            _source_error(
                                name=name,
                                code=getattr(exc, "code", "malformed_response"),
                                message=str(exc),
                                occurred_at=observed_at,
                                retryable=getattr(exc, "retryable", False),
                                source_url="https://api.osv.dev/v1/querybatch",
                            )
                        )
                    pending = []
                    break

                next_pending: list[dict[str, str | None]] = []
                for item, raw_result in zip(pending, results, strict=True):
                    name = str(item["name"])
                    version = str(item["version"])
                    try:
                        result = _mapping(raw_result, "OSV batch item")
                        raw_vulns = result.get("vulns", [])
                        if not isinstance(raw_vulns, list):
                            raise OsvDataError("OSV vulnerability list is malformed")
                        for raw_vuln in raw_vulns:
                            brief = _mapping(raw_vuln, "OSV vulnerability brief")
                            advisory_id = bounded_text(brief.get("id"), limit=120)
                            if not advisory_id:
                                raise OsvDataError("OSV vulnerability omits id")
                            detail_count += 1
                            if detail_count > MAX_ADVISORIES:
                                raise OsvDataError(
                                    f"OSV advisory count exceeds {MAX_ADVISORIES}"
                                )
                            output[name].append(
                                self._fetch_detail(
                                    advisory_id=advisory_id,
                                    name=name,
                                    version=version,
                                )
                            )
                        token = bounded_text(result.get("next_page_token"), limit=1000)
                        if token:
                            next_pending.append(
                                {
                                    "name": name,
                                    "version": version,
                                    "page_token": token,
                                }
                            )
                    except (SourceRequestError, OsvDataError, ValueError) as exc:
                        incomplete.add(name)
                        errors.append(
                            _source_error(
                                name=name,
                                code=getattr(exc, "code", "malformed_response"),
                                message=str(exc),
                                occurred_at=observed_at,
                                retryable=getattr(exc, "retryable", False),
                                source_url=getattr(
                                    exc,
                                    "url",
                                    "https://api.osv.dev/v1/querybatch",
                                ),
                            )
                        )
                pending = next_pending
            if pending:
                for item in pending:
                    name = str(item["name"])
                    incomplete.add(name)
                    errors.append(
                        _source_error(
                            name=name,
                            code="pagination_limit",
                            message=f"OSV pagination exceeded {MAX_PAGES} pages",
                            occurred_at=observed_at,
                            retryable=False,
                            source_url="https://api.osv.dev/v1/querybatch",
                        )
                    )

        return OsvResult(
            vulnerabilities={
                name: tuple(sorted(items, key=lambda item: item.id))
                for name, items in output.items()
            },
            errors=tuple(errors),
            incomplete_packages=frozenset(incomplete),
        )

    def _fetch_detail(
        self, *, advisory_id: str, name: str, version: str
    ) -> VulnerabilitySnapshot:
        api_url = f"https://api.osv.dev/v1/vulns/{quote(advisory_id, safe='')}"
        data = _mapping(
            self.http.request_json(
                "GET", api_url, max_response_bytes=2 * 1024 * 1024
            ).data,
            "OSV vulnerability detail",
        )
        returned_id = bounded_text(data.get("id"), limit=120)
        if returned_id != advisory_id:
            raise OsvDataError("OSV detail id does not match the requested advisory")
        aliases = normalise_string_list(
            data.get("aliases"), item_limit=120, max_items=100
        )
        references: list[VulnerabilityReference] = []
        raw_references = data.get("references", [])
        if not isinstance(raw_references, list):
            raise OsvDataError("OSV references are malformed")
        for raw_reference in raw_references[:MAX_REFERENCES]:
            reference = _mapping(raw_reference, "OSV reference")
            url = normalise_url(reference.get("url"))
            ref_type = bounded_text(reference.get("type"), limit=40) or "WEB"
            if url:
                references.append(VulnerabilityReference(type=ref_type, url=url))
        severity_type, severity_score, severity_label = _severity(data)
        return VulnerabilitySnapshot(
            id=advisory_id,
            aliases=aliases,
            affected_package=name,
            affected_version=version,
            severity_type=severity_type,
            severity_score=severity_score,
            severity_label=severity_label,
            published=_parse_datetime(data.get("published")),
            modified=_parse_datetime(data.get("modified")),
            references=tuple(
                sorted(
                    set(references),
                    key=lambda item: (item.type, item.url),
                )
            ),
            source_url=f"https://osv.dev/vulnerability/{quote(advisory_id, safe='')}",
        )


def _severity(
    data: Mapping[str, Any],
) -> tuple[str | None, str | None, SeverityLabel | None]:
    raw_severity = data.get("severity", [])
    if isinstance(raw_severity, list):
        for item in raw_severity:
            if not isinstance(item, Mapping):
                continue
            severity_type = bounded_text(item.get("type"), limit=40)
            score = bounded_text(item.get("score"), limit=160)
            if severity_type and score:
                label = _numeric_severity(score)
                if label:
                    return severity_type, score, label
                candidate = score.casefold()
                if candidate in {"low", "medium", "high", "critical"}:
                    return severity_type, score, cast(SeverityLabel, candidate)
                return severity_type, score, None
    database_specific = data.get("database_specific")
    if isinstance(database_specific, Mapping):
        raw_label = bounded_text(database_specific.get("severity"), limit=40)
        if raw_label and raw_label.casefold() in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            label = cast(SeverityLabel, raw_label.casefold())
            return "database_specific", raw_label, label
    return None, None, None


def _numeric_severity(score: str) -> SeverityLabel | None:
    try:
        number = float(score)
    except ValueError:
        return None
    if not 0 <= number <= MAX_CVSS_SCORE:
        return None
    thresholds: tuple[tuple[float, SeverityLabel], ...] = (
        (9, "critical"),
        (7, "high"),
        (4, "medium"),
        (0.000_001, "low"),
    )
    for threshold, label in thresholds:
        if number >= threshold:
            return label
    return None


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OsvDataError(f"{label} must be an object")
    return value


def _parse_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_TIMESTAMP_LENGTH:
        raise OsvDataError("OSV timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OsvDataError("OSV timestamp is malformed") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _source_error(
    *,
    name: str,
    code: str,
    message: str,
    occurred_at: datetime,
    retryable: bool,
    source_url: str,
) -> SourceError:
    return SourceError(
        source="osv",
        package_name=name,
        code=code[:80],
        message=message[:2000],
        occurred_at=occurred_at,
        retryable=retryable,
        source_url=source_url,
    )
