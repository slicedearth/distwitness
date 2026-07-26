from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
import pytest

from distwitness.http import BoundedHttpClient
from distwitness.models import PackageConfig, ProvenanceState
from distwitness.pypi import (
    INDEX_ACCEPT,
    MAX_INDEX_FILES,
    MAX_INDEX_RESPONSE_BYTES,
    MAX_RELEASE_LOOKUPS,
    MAX_VERSIONS,
    PackageDataError,
    PyPIClient,
    select_version,
)
from tests.factories import NOW, pypi_index, pypi_project


def _http(handler: httpx.MockTransport) -> BoundedHttpClient:
    return BoundedHttpClient(
        user_agent="DistWitness tests (+https://example.test)",
        client=httpx.Client(transport=handler),
        sleep=lambda _delay: None,
        jitter=lambda _start, _end: 0,
    )


def test_select_version_excludes_prereleases_and_invalid_versions() -> None:
    versions: list[object] = ["1.0.0", "2.0.0rc1", "not-a-version"]
    assert select_version(versions, include_prereleases=False) == "1.0.0"
    assert select_version(versions, include_prereleases=True) == "2.0.0rc1"


def test_select_version_fails_when_index_versions_are_ambiguous() -> None:
    with pytest.raises(PackageDataError, match="no selectable"):
        select_version(["not-pep440"], include_prereleases=False)
    with pytest.raises(PackageDataError, match="duplicate"):
        select_version(["1.0", "1.0"], include_prereleases=False)
    with pytest.raises(PackageDataError, match="exceeds"):
        select_version(["1.0"] * (MAX_VERSIONS + 1), include_prereleases=False)


def test_fetch_package_uses_index_then_selected_release_metadata() -> None:
    integrity = json.loads(
        Path("tests/fixtures/integrity-present.json").read_text(encoding="utf-8")
    )
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.startswith("/simple/"):
            assert request.headers["accept"] == INDEX_ACCEPT
            return httpx.Response(200, json=pypi_index())
        if request.url.path.startswith("/integrity/"):
            return httpx.Response(200, json=integrity)
        assert request.url.path == "/pypi/demo/1.0.0/json"
        return httpx.Response(200, json=pypi_project())

    snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
        PackageConfig(name="Demo"),
        include_prereleases=False,
        observed_at=NOW,
    )
    assert paths[:2] == ["/simple/demo/", "/pypi/demo/1.0.0/json"]
    assert "/pypi/demo/json" not in paths
    assert snapshot.name == "demo"
    assert snapshot.release.version == "1.0.0"
    assert snapshot.release_discovery == "pypi-index-v1"
    assert snapshot.index_api_version == "1.4"
    assert snapshot.release.files[0].python_tags == ("py3-none-any",)
    assert snapshot.release.files[0].provenance.state == ProvenanceState.PRESENT
    assert snapshot.release.files[0].provenance.publishers == (
        "GitHub / example/demo / release.yml / pypi",
    )
    assert snapshot.requires_dist == ("httpx>=0.28",)


def test_index_response_can_use_its_explicit_eight_megabyte_bound() -> None:
    index_data = pypi_index()
    index_data["padding"] = "x" * (4 * 1024 * 1024)
    encoded = json.dumps(index_data).encode()
    assert 4 * 1024 * 1024 < len(encoded) < MAX_INDEX_RESPONSE_BYTES

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/simple/"):
            return httpx.Response(
                200,
                content=encoded,
                headers={"content-type": INDEX_ACCEPT},
            )
        if request.url.path.startswith("/integrity/"):
            return httpx.Response(404)
        return httpx.Response(200, json=pypi_project())

    snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
        PackageConfig(name="demo"),
        include_prereleases=False,
        observed_at=NOW,
    )
    assert snapshot.release.version == "1.0.0"


def test_absent_and_unavailable_provenance_states() -> None:
    for status, expected in (
        (404, ProvenanceState.ABSENT),
        (403, ProvenanceState.UNAVAILABLE),
        (406, ProvenanceState.UNSUPPORTED),
    ):

        def handler(
            request: httpx.Request, status_code: int = status
        ) -> httpx.Response:
            if request.url.path.startswith("/simple/"):
                return httpx.Response(200, json=pypi_index())
            if request.url.path.startswith("/integrity/"):
                return httpx.Response(status_code)
            return httpx.Response(200, json=pypi_project())

        snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
            PackageConfig(name="demo"),
            include_prereleases=False,
            observed_at=NOW,
        )
        assert snapshot.release.files[0].provenance.state == expected
        if status == 403:
            assert snapshot.source_errors[0].code == "http_403"


def test_failed_provenance_request_is_not_absent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/simple/"):
            return httpx.Response(200, json=pypi_index())
        if request.url.path.startswith("/integrity/"):
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(200, json=pypi_project())

    snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
        PackageConfig(name="demo"),
        include_prereleases=False,
        observed_at=NOW,
    )
    assert snapshot.release.files[0].provenance.state == ProvenanceState.REQUEST_FAILED
    assert snapshot.source_errors


def test_all_yanked_release_is_represented_accurately() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/simple/"):
            return httpx.Response(200, json=pypi_index())
        if request.url.path.startswith("/integrity/"):
            return httpx.Response(404)
        return httpx.Response(200, json=pypi_project(yanked=True))

    snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
        PackageConfig(name="demo"),
        include_prereleases=False,
        observed_at=NOW,
    )
    assert snapshot.release.yanked is True
    assert snapshot.release.all_files_yanked is True


@pytest.mark.parametrize(
    ("index_data", "release_data"),
    [
        ([], pypi_project()),
        ({"meta": {"api-version": "1.4"}, "name": "demo"}, pypi_project()),
        (pypi_index(api_version="2.0"), pypi_project()),
        (pypi_index(api_version="1.0"), pypi_project()),
        (pypi_index(versions=["1.0", "1.0"]), pypi_project()),
        (pypi_index(name="other"), pypi_project()),
        (pypi_index(), pypi_project(name="Other")),
        (pypi_index(), pypi_project(version="2.0.0")),
        (pypi_index(), pypi_project(filename="../../escape.whl")),
        (pypi_index(), pypi_project(filename="demo.whl", size=-1)),
    ],
)
def test_malformed_or_unsafe_pypi_data_fails_closed(
    index_data: object,
    release_data: object,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/simple/"):
            return httpx.Response(200, json=index_data)
        if request.url.path.startswith("/integrity/"):
            return httpx.Response(404)
        return httpx.Response(200, json=release_data)

    with pytest.raises(PackageDataError):
        PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
            PackageConfig(name="demo"),
            include_prereleases=False,
            observed_at=NOW,
        )


@pytest.mark.parametrize("missing_status", [200, 404])
def test_missing_higher_release_falls_back_within_bounded_window(
    missing_status: int,
) -> None:
    requested_releases: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/simple/"):
            return httpx.Response(
                200,
                json=pypi_index(versions=["2.0.0", "1.0.0"]),
            )
        if request.url.path.startswith("/integrity/"):
            return httpx.Response(404)
        requested_releases.append(request.url.path)
        if request.url.path.endswith("/2.0.0/json"):
            if missing_status == 404:
                return httpx.Response(404)
            empty = pypi_project(version="2.0.0")
            empty["urls"] = []
            return httpx.Response(200, json=empty)
        return httpx.Response(200, json=pypi_project())

    snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
        PackageConfig(name="demo"),
        include_prereleases=False,
        observed_at=NOW,
    )
    assert snapshot.release.version == "1.0.0"
    assert requested_releases == [
        "/pypi/demo/2.0.0/json",
        "/pypi/demo/1.0.0/json",
    ]


def test_index_and_release_lookup_counts_are_bounded() -> None:
    oversized = pypi_index()
    oversized["files"] = [{}] * (MAX_INDEX_FILES + 1)

    def oversized_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.startswith("/simple/")
        return httpx.Response(200, json=oversized)

    with pytest.raises(PackageDataError, match="file count exceeds"):
        PyPIClient(_http(httpx.MockTransport(oversized_handler))).fetch_package(
            PackageConfig(name="demo"),
            include_prereleases=False,
            observed_at=NOW,
        )

    candidates: list[object] = [
        f"1.0.{index}" for index in range(MAX_RELEASE_LOOKUPS + 1)
    ]
    release_requests = 0

    def missing_handler(request: httpx.Request) -> httpx.Response:
        nonlocal release_requests
        if request.url.path.startswith("/simple/"):
            return httpx.Response(200, json=pypi_index(versions=candidates))
        release_requests += 1
        return httpx.Response(404)

    with pytest.raises(PackageDataError, match="bounded"):
        PyPIClient(_http(httpx.MockTransport(missing_handler))).fetch_package(
            PackageConfig(name="demo"),
            include_prereleases=False,
            observed_at=NOW,
        )
    assert release_requests == MAX_RELEASE_LOOKUPS


def test_newer_index_minor_version_uses_known_fields_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/simple/"):
            return httpx.Response(200, json=pypi_index(api_version="1.9"))
        if request.url.path.startswith("/integrity/"):
            return httpx.Response(404)
        return httpx.Response(200, json=pypi_project())

    with caplog.at_level(logging.WARNING, logger="distwitness.pypi"):
        snapshot = PyPIClient(_http(httpx.MockTransport(handler))).fetch_package(
            PackageConfig(name="demo"),
            include_prereleases=False,
            observed_at=NOW,
        )
    assert snapshot.index_api_version == "1.9"
    assert "newer than the tested" in caplog.text
