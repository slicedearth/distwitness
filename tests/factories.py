"""Small handcrafted contracts used by offline tests."""

from __future__ import annotations

from datetime import UTC, datetime

from distwitness.models import (
    PackageSnapshot,
    ProvenanceSnapshot,
    ProvenanceState,
    ReleaseFileSnapshot,
    ReleaseSnapshot,
    SourceError,
    VulnerabilityReference,
    VulnerabilitySnapshot,
)

NOW = datetime(2026, 7, 26, 4, 0, tzinfo=UTC)


def provenance(
    state: ProvenanceState = ProvenanceState.ABSENT,
    *,
    publishers: tuple[str, ...] = (),
) -> ProvenanceSnapshot:
    return ProvenanceSnapshot(
        state=state,
        publishers=publishers,
        attestation_count=1 if state == ProvenanceState.PRESENT else 0,
        source_url=(
            "https://pypi.org/integrity/demo/1.0.0/"
            "demo-1.0.0-py3-none-any.whl/provenance"
        ),
        observed_at=NOW,
    )


def release_file(
    *,
    filename: str = "demo-1.0.0-py3-none-any.whl",
    sha256: str = "a" * 64,
    size: int = 200_000,
    package_type: str = "bdist_wheel",
    yanked: bool = False,
    provenance_state: ProvenanceState = ProvenanceState.ABSENT,
    publishers: tuple[str, ...] = (),
) -> ReleaseFileSnapshot:
    return ReleaseFileSnapshot(
        filename=filename,
        sha256=sha256,
        size=size,
        package_type=package_type,
        upload_time=NOW,
        python_version="py3",
        python_tags=("py3-none-any",),
        requires_python=">=3.12",
        yanked=yanked,
        provenance=provenance(provenance_state, publishers=publishers),
    )


def vulnerability(
    advisory_id: str = "GHSA-test-0000",
    *,
    severity_label: str | None = None,
) -> VulnerabilitySnapshot:
    return VulnerabilitySnapshot.model_validate(
        {
            "id": advisory_id,
            "aliases": ["CVE-2026-0001"],
            "affected_package": "demo",
            "affected_version": "1.0.0",
            "severity_type": "CVSS_V3",
            "severity_score": "9.8" if severity_label else None,
            "severity_label": severity_label,
            "published": NOW,
            "modified": NOW,
            "references": [
                VulnerabilityReference(
                    type="ADVISORY",
                    url=f"https://osv.dev/vulnerability/{advisory_id}",
                )
            ],
            "source_url": f"https://osv.dev/vulnerability/{advisory_id}",
        }
    )


def source_error(
    *,
    source: str = "osv",
    code: str = "request_failed",
) -> SourceError:
    return SourceError.model_validate(
        {
            "source": source,
            "package_name": "demo",
            "code": code,
            "message": "source data unavailable",
            "occurred_at": NOW,
            "retryable": True,
            "source_url": (
                "https://api.osv.dev/v1/querybatch"
                if source == "osv"
                else "https://pypi.org/simple/demo/"
            ),
        }
    )


def snapshot(
    *,
    version: str = "1.0.0",
    files: tuple[ReleaseFileSnapshot, ...] | None = None,
    requires_python: str | None = ">=3.12",
    requires_dist: tuple[str, ...] = ("httpx>=0.28",),
    license_expression: str | None = "MIT",
    project_urls: dict[str, str] | None = None,
    vulnerabilities: tuple[VulnerabilitySnapshot, ...] = (),
    source_errors: tuple[SourceError, ...] = (),
    display_name: str = "Demo",
) -> PackageSnapshot:
    selected_files = files or (release_file(),)
    all_yanked = all(item.yanked for item in selected_files)
    return PackageSnapshot(
        name="demo",
        display_name=display_name,
        collected_at=NOW,
        release_discovery="pypi-index-v1",
        index_api_version="1.4",
        release=ReleaseSnapshot(
            version=version,
            yanked=all_yanked,
            all_files_yanked=all_yanked,
            files=selected_files,
            source_url=f"https://pypi.org/project/demo/{version}/",
            source_timestamp=NOW,
        ),
        requires_python=requires_python,
        requires_dist=requires_dist,
        license_expression=license_expression,
        declared_license="MIT License",
        license_classifiers=("License :: OSI Approved :: MIT License",),
        project_urls=project_urls or {"Source": "https://example.test/demo/"},
        vulnerabilities=vulnerabilities,
        source_errors=source_errors,
    )


def pypi_project(
    *,
    name: str = "Demo",
    version: str = "1.0.0",
    filename: str = "demo-1.0.0-py3-none-any.whl",
    yanked: bool = False,
    size: int = 200_000,
) -> dict[str, object]:
    file_record: dict[str, object] = {
        "filename": filename,
        "digests": {"sha256": "a" * 64},
        "size": size,
        "packagetype": "bdist_wheel",
        "upload_time_iso_8601": "2026-07-26T04:00:00Z",
        "python_version": "py3",
        "requires_python": ">=3.12",
        "yanked": yanked,
        "yanked_reason": "superseded" if yanked else None,
    }
    return {
        "info": {
            "name": name,
            "version": version,
            "requires_python": ">=3.12",
            "requires_dist": ["httpx>=0.28"],
            "license_expression": "MIT",
            "license": "MIT License",
            "classifiers": ["License :: OSI Approved :: MIT License"],
            "project_urls": {"Source": "https://example.test/demo"},
        },
        "urls": [file_record],
    }


def pypi_index(
    *,
    name: str = "demo",
    version: str = "1.0.0",
    filename: str = "demo-1.0.0-py3-none-any.whl",
    api_version: str = "1.4",
    versions: list[object] | None = None,
) -> dict[str, object]:
    """Return a minimal JSON Simple/Index API project response."""

    selected_versions = versions if versions is not None else [version, "2.0.0b1"]
    return {
        "meta": {"api-version": api_version, "_last-serial": 1},
        "name": name,
        "project-status": {"status": "active"},
        "versions": selected_versions,
        "files": [
            {
                "filename": filename,
                "url": f"https://files.pythonhosted.org/{filename}",
                "hashes": {"sha256": "a" * 64},
                "requires-python": ">=3.12",
                "size": 200_000,
                "upload-time": "2026-07-26T04:00:00Z",
                "yanked": False,
                "provenance": None,
            }
        ],
    }
