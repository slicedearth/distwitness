"""PyPI Index, release, and Integrity collection without distribution downloads."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from distwitness.http import BoundedHttpClient, SourceRequestError
from distwitness.models import (
    PackageConfig,
    PackageSnapshot,
    ProvenanceSnapshot,
    ProvenanceState,
    ReleaseFileSnapshot,
    ReleaseSnapshot,
    SourceError,
)
from distwitness.normalise import (
    NormalisationError,
    bounded_text,
    licensing_classifiers,
    normalise_package_name,
    normalise_requirements,
    normalise_string_list,
    normalise_urls,
)

LOGGER = logging.getLogger(__name__)
INDEX_ACCEPT = "application/vnd.pypi.simple.v1+json"
SUPPORTED_INDEX_MAJOR = 1
KNOWN_INDEX_MINOR = 4
MIN_INDEX_MINOR = 1
MAX_VERSIONS = 10_000
MAX_INDEX_FILES = 25_000
MAX_INDEX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_RELEASE_LOOKUPS = 20
MAX_FILES_PER_RELEASE = 200
MAX_ATTESTATION_BUNDLES = 100
SHA256_HEX_LENGTH = 64
MAX_TIMESTAMP_LENGTH = 80
INDEX_VERSION_PATTERN = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)$")
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_NOT_ACCEPTABLE = 406


class PackageDataError(ValueError):
    """Raised when PyPI metadata is ambiguous, malformed, or unsafe."""


def select_version(versions: object, *, include_prereleases: bool) -> str:
    """Select the highest valid PEP 440 version reported by the Index API."""

    candidates = _eligible_versions(
        versions,
        include_prereleases=include_prereleases,
    )
    return candidates[0]


def _eligible_versions(
    versions: object,
    *,
    include_prereleases: bool,
) -> tuple[str, ...]:
    if not isinstance(versions, list):
        raise PackageDataError("PyPI Index versions must be an array")
    if len(versions) > MAX_VERSIONS:
        raise PackageDataError(f"version count exceeds {MAX_VERSIONS}")
    candidates: list[tuple[Version, str]] = []
    seen: set[str] = set()
    for raw_version in versions:
        if not isinstance(raw_version, str):
            continue
        if raw_version in seen:
            raise PackageDataError("PyPI Index versions contain a duplicate")
        seen.add(raw_version)
        try:
            parsed = Version(raw_version)
        except InvalidVersion:
            continue
        if not include_prereleases and (parsed.is_prerelease or parsed.is_devrelease):
            continue
        candidates.append((parsed, raw_version))
    if not candidates:
        qualifier = " including pre-releases" if include_prereleases else ""
        raise PackageDataError(f"no selectable Index API version{qualifier}")
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return tuple(item[1] for item in candidates)


class PyPIClient:
    """Fixed-purpose collector for one configured PyPI project."""

    def __init__(self, http: BoundedHttpClient) -> None:
        self.http = http

    def fetch_package(
        self,
        package: PackageConfig,
        *,
        include_prereleases: bool,
        observed_at: datetime,
    ) -> PackageSnapshot:
        """Fetch, select, and normalise one package and per-file provenance."""

        name = package.normalised_name
        (
            index_api_version,
            selected,
            info,
            selected_files_raw,
        ) = self._fetch_selected_release(
            name=name,
            include_prereleases=include_prereleases,
        )

        if len(selected_files_raw) > MAX_FILES_PER_RELEASE:
            raise PackageDataError(
                f"selected release exceeds {MAX_FILES_PER_RELEASE} files"
            )
        files: list[ReleaseFileSnapshot] = []
        source_errors: list[SourceError] = []
        for raw_file in selected_files_raw:
            file_data = _mapping(raw_file, "PyPI release file")
            parsed_file, error = self._normalise_file(
                name=name,
                version=selected,
                raw=file_data,
                observed_at=observed_at,
            )
            files.append(parsed_file)
            if error:
                source_errors.append(error)
        files.sort(key=lambda item: item.filename)
        if not files:
            raise PackageDataError("selected release has no valid files")

        all_yanked = all(item.yanked for item in files)
        release_timestamp = max(
            (item.upload_time for item in files if item.upload_time is not None),
            default=None,
        )
        release = ReleaseSnapshot(
            version=selected,
            yanked=all_yanked,
            all_files_yanked=all_yanked,
            files=tuple(files),
            source_url=f"https://pypi.org/project/{quote(name, safe='')}/"
            f"{quote(selected, safe='')}/",
            source_timestamp=release_timestamp,
        )
        classifiers = normalise_string_list(info.get("classifiers"), max_items=500)
        try:
            requirements = normalise_requirements(info.get("requires_dist"))
            urls = normalise_urls(info.get("project_urls"))
        except NormalisationError as exc:
            raise PackageDataError(str(exc)) from exc
        display_name = bounded_text(info.get("name"), limit=100) or name
        return PackageSnapshot(
            name=name,
            display_name=display_name,
            collected_at=observed_at,
            release_discovery="pypi-index-v1",
            index_api_version=index_api_version,
            release=release,
            requires_python=bounded_text(info.get("requires_python"), limit=500),
            requires_dist=requirements,
            license_expression=bounded_text(info.get("license_expression"), limit=500),
            declared_license=bounded_text(info.get("license"), limit=500),
            license_classifiers=licensing_classifiers(classifiers),
            project_urls=urls,
            source_errors=tuple(source_errors),
        )

    def _fetch_selected_release(
        self,
        *,
        name: str,
        include_prereleases: bool,
    ) -> tuple[str, str, Mapping[str, Any], list[Any]]:
        index_url = f"https://pypi.org/simple/{quote(name, safe='')}/"
        index_response = self.http.request_json(
            "GET",
            index_url,
            accept=INDEX_ACCEPT,
            max_response_bytes=MAX_INDEX_RESPONSE_BYTES,
        )
        index_data = _mapping(index_response.data, "PyPI Index project response")
        index_api_version = _index_api_version(index_data)
        index_name = bounded_text(index_data.get("name"), limit=100)
        if index_name != name:
            raise PackageDataError("PyPI Index project name does not match request")
        index_files = index_data.get("files")
        if not isinstance(index_files, list):
            raise PackageDataError("PyPI Index files must be an array")
        if len(index_files) > MAX_INDEX_FILES:
            raise PackageDataError(f"Index file count exceeds {MAX_INDEX_FILES}")
        candidates = _eligible_versions(
            index_data.get("versions"),
            include_prereleases=include_prereleases,
        )
        selected: str | None = None
        info: Mapping[str, Any] | None = None
        selected_files_raw: list[Any] | None = None
        for candidate in candidates[:MAX_RELEASE_LOOKUPS]:
            release_api_url = (
                f"https://pypi.org/pypi/{quote(name, safe='')}/"
                f"{quote(candidate, safe='')}/json"
            )
            release_response = self.http.request_json(
                "GET",
                release_api_url,
                accepted_statuses=frozenset({200, HTTP_NOT_FOUND}),
            )
            if release_response.status_code == HTTP_NOT_FOUND:
                continue
            release_data = _mapping(
                release_response.data,
                "PyPI release response",
            )
            urls = release_data.get("urls")
            if not isinstance(urls, list):
                raise PackageDataError("selected release files are malformed")
            if not urls:
                continue
            candidate_info = _mapping(release_data.get("info"), "PyPI release info")
            _validate_selected_release(
                name=name,
                selected=candidate,
                info=candidate_info,
            )
            selected = candidate
            info = candidate_info
            selected_files_raw = urls
            break
        if selected is None or info is None or selected_files_raw is None:
            raise PackageDataError(
                "no selectable release with files was found within the bounded "
                f"{MAX_RELEASE_LOOKUPS}-version lookup window"
            )
        return index_api_version, selected, info, selected_files_raw

    def _normalise_file(
        self,
        *,
        name: str,
        version: str,
        raw: Mapping[str, Any],
        observed_at: datetime,
    ) -> tuple[ReleaseFileSnapshot, SourceError | None]:
        filename = bounded_text(raw.get("filename"), limit=300)
        if (
            not filename
            or "/" in filename
            or "\\" in filename
            or filename in {".", ".."}
        ):
            raise PackageDataError("release filename is unsafe")
        digests = _mapping(raw.get("digests"), "release-file digests")
        sha256 = bounded_text(digests.get("sha256"), limit=64)
        if sha256 is not None:
            sha256 = sha256.lower()
            if len(sha256) != SHA256_HEX_LENGTH or any(
                char not in "0123456789abcdef" for char in sha256
            ):
                raise PackageDataError("release file has an invalid SHA-256 digest")
        size = raw.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise PackageDataError("release file has an invalid size")
        package_type = bounded_text(raw.get("packagetype"), limit=80)
        if not package_type:
            raise PackageDataError("release file omits package type")
        upload_time = _parse_datetime(raw.get("upload_time_iso_8601"))
        python_version = bounded_text(raw.get("python_version"), limit=80)
        requires_python = bounded_text(raw.get("requires_python"), limit=500)
        yanked = raw.get("yanked", False)
        if not isinstance(yanked, bool):
            raise PackageDataError("release yanked state is malformed")
        provenance, source_error = self._fetch_provenance(
            name=name,
            version=version,
            filename=filename,
            observed_at=observed_at,
        )
        return (
            ReleaseFileSnapshot(
                filename=filename,
                sha256=sha256,
                size=size,
                package_type=package_type,
                upload_time=upload_time,
                python_version=python_version,
                python_tags=_wheel_tags(filename),
                requires_python=requires_python,
                yanked=yanked,
                yanked_reason=bounded_text(raw.get("yanked_reason"), limit=500),
                provenance=provenance,
            ),
            source_error,
        )

    def _fetch_provenance(
        self,
        *,
        name: str,
        version: str,
        filename: str,
        observed_at: datetime,
    ) -> tuple[ProvenanceSnapshot, SourceError | None]:
        url = (
            f"https://pypi.org/integrity/{quote(name, safe='')}/"
            f"{quote(version, safe='')}/{quote(filename, safe='')}/provenance"
        )
        try:
            response = self.http.request_json(
                "GET",
                url,
                accepted_statuses=frozenset({200, 403, 404, 406}),
                accept="application/vnd.pypi.integrity.v1+json",
                max_response_bytes=2 * 1024 * 1024,
            )
        except SourceRequestError as exc:
            return (
                ProvenanceSnapshot(
                    state=ProvenanceState.REQUEST_FAILED,
                    source_url=url,
                    observed_at=observed_at,
                ),
                _source_error(
                    name=name,
                    code=exc.code,
                    message=str(exc),
                    occurred_at=observed_at,
                    retryable=exc.retryable,
                    source_url=url,
                ),
            )
        if response.status_code == HTTP_NOT_FOUND:
            return (
                ProvenanceSnapshot(
                    state=ProvenanceState.ABSENT,
                    source_url=url,
                    observed_at=observed_at,
                ),
                None,
            )
        if response.status_code == HTTP_FORBIDDEN:
            return (
                ProvenanceSnapshot(
                    state=ProvenanceState.UNAVAILABLE,
                    source_url=url,
                    observed_at=observed_at,
                ),
                _source_error(
                    name=name,
                    code="http_403",
                    message="PyPI temporarily disabled Integrity API access",
                    occurred_at=observed_at,
                    retryable=True,
                    source_url=url,
                ),
            )
        if response.status_code == HTTP_NOT_ACCEPTABLE:
            return (
                ProvenanceSnapshot(
                    state=ProvenanceState.UNSUPPORTED,
                    source_url=url,
                    observed_at=observed_at,
                ),
                None,
            )
        try:
            data = _mapping(response.data, "Integrity response")
            bundles = data.get("attestation_bundles")
            if not isinstance(bundles, list) or len(bundles) > MAX_ATTESTATION_BUNDLES:
                raise PackageDataError("Integrity attestation bundles are malformed")
            publishers: set[str] = set()
            attestation_count = 0
            for raw_bundle in bundles:
                bundle = _mapping(raw_bundle, "Integrity attestation bundle")
                attestations = bundle.get("attestations")
                if not isinstance(attestations, list):
                    raise PackageDataError("Integrity attestations are malformed")
                attestation_count += len(attestations)
                publisher = bundle.get("publisher")
                if isinstance(publisher, Mapping):
                    parts = [
                        bounded_text(publisher.get(key), limit=150)
                        for key in ("kind", "repository", "workflow", "environment")
                    ]
                    identity = " / ".join(part for part in parts if part)
                    if identity:
                        publishers.add(identity)
            state = (
                ProvenanceState.PRESENT
                if bundles and attestation_count > 0
                else ProvenanceState.ABSENT
            )
            return (
                ProvenanceSnapshot(
                    state=state,
                    publishers=tuple(sorted(publishers)),
                    attestation_count=attestation_count,
                    source_url=url,
                    observed_at=observed_at,
                ),
                None,
            )
        except (NormalisationError, PackageDataError, TypeError, ValueError) as exc:
            return (
                ProvenanceSnapshot(
                    state=ProvenanceState.MALFORMED_RESPONSE,
                    source_url=url,
                    observed_at=observed_at,
                ),
                _source_error(
                    name=name,
                    code="malformed_response",
                    message=str(exc),
                    occurred_at=observed_at,
                    retryable=False,
                    source_url=url,
                ),
            )


def _wheel_tags(filename: str) -> tuple[str, ...]:
    if not filename.endswith(".whl"):
        return ()
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return ()
    return tuple(sorted(str(tag) for tag in tags))


def _index_api_version(data: Mapping[str, Any]) -> str:
    meta = _mapping(data.get("meta"), "PyPI Index meta")
    raw_version = meta.get("api-version", "1.0")
    if not isinstance(raw_version, str):
        raise PackageDataError("PyPI Index API version is malformed")
    match = INDEX_VERSION_PATTERN.fullmatch(raw_version)
    if not match:
        raise PackageDataError("PyPI Index API version is malformed")
    major = int(match.group("major"))
    minor = int(match.group("minor"))
    if major != SUPPORTED_INDEX_MAJOR:
        raise PackageDataError(
            f"unsupported PyPI Index API major version: {raw_version}"
        )
    if minor < MIN_INDEX_MINOR:
        raise PackageDataError(
            "PyPI Index API does not provide the required versions metadata"
        )
    if minor > KNOWN_INDEX_MINOR:
        LOGGER.warning(
            "PyPI Index API %s is newer than the tested 1.%s contract; "
            "continuing with known fields",
            raw_version,
            KNOWN_INDEX_MINOR,
        )
    return raw_version


def _validate_selected_release(
    *,
    name: str,
    selected: str,
    info: Mapping[str, Any],
) -> None:
    reported_name = bounded_text(info.get("name"), limit=100)
    if reported_name is None:
        raise PackageDataError("PyPI release info omits project name")
    try:
        normalised_reported_name = normalise_package_name(reported_name)
    except NormalisationError as exc:
        raise PackageDataError("PyPI release project name is malformed") from exc
    if normalised_reported_name != name:
        raise PackageDataError("PyPI release project name does not match request")
    reported_version = bounded_text(info.get("version"), limit=200)
    if reported_version is None:
        raise PackageDataError("PyPI release info omits version")
    try:
        if Version(reported_version) != Version(selected):
            raise PackageDataError("PyPI release version does not match selection")
    except InvalidVersion as exc:
        raise PackageDataError("PyPI release version is malformed") from exc


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PackageDataError(f"{label} must be an object")
    return value


def _parse_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_TIMESTAMP_LENGTH:
        raise PackageDataError("source timestamp is malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PackageDataError("source timestamp is malformed") from exc
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
        source="pypi_integrity",
        package_name=name,
        code=code[:80],
        message=message[:2000],
        occurred_at=occurred_at,
        retryable=retryable,
        source_url=source_url,
    )
