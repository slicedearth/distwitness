from __future__ import annotations

import json
from pathlib import Path

import httpx

from distwitness.http import BoundedHttpClient
from distwitness.osv import OsvClient
from tests.factories import NOW, snapshot


def _client(handler: httpx.MockTransport) -> OsvClient:
    return OsvClient(
        BoundedHttpClient(
            user_agent="DistWitness tests (+https://example.test)",
            client=httpx.Client(transport=handler),
            sleep=lambda _delay: None,
            jitter=lambda _start, _end: 0,
        )
    )


def test_batch_response_order_maps_to_sorted_package_queries() -> None:
    seen_names: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            payload = json.loads(request.content)
            seen_names.extend(item["package"]["name"] for item in payload["queries"])
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-alpha", "modified": "2026-01-01Z"}]},
                        {"vulns": [{"id": "GHSA-zulu", "modified": "2026-01-01Z"}]},
                    ]
                },
            )
        advisory_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(
            200,
            json={
                "id": advisory_id,
                "aliases": [],
                "modified": "2026-07-21T00:00:00Z",
                "references": [],
            },
        )

    alpha = snapshot().model_copy(update={"name": "alpha", "display_name": "Alpha"})
    zulu = snapshot().model_copy(update={"name": "zulu", "display_name": "Zulu"})
    result = _client(httpx.MockTransport(handler)).query_packages(
        {"zulu": zulu, "alpha": alpha},
        observed_at=NOW,
    )
    assert seen_names == ["alpha", "zulu"]
    assert result.vulnerabilities["alpha"][0].id == "GHSA-alpha"
    assert result.vulnerabilities["zulu"][0].id == "GHSA-zulu"
    assert not result.errors


def test_querybatch_pagination_is_per_query() -> None:
    batch_calls = 0
    queried_tokens: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal batch_calls
        if request.url.path == "/v1/querybatch":
            batch_calls += 1
            payload = json.loads(request.content)
            queried_tokens.append(payload["queries"][0].get("page_token"))
            if batch_calls == 1:
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {
                                "vulns": [{"id": "GHSA-one"}],
                                "next_page_token": "page-two",
                            }
                        ]
                    },
                )
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "GHSA-two"}]}]}
            )
        advisory_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(
            200,
            json={"id": advisory_id, "aliases": [], "references": []},
        )

    result = _client(httpx.MockTransport(handler)).query_packages(
        {"demo": snapshot()}, observed_at=NOW
    )
    assert queried_tokens == [None, "page-two"]
    assert [item.id for item in result.vulnerabilities["demo"]] == [
        "GHSA-one",
        "GHSA-two",
    ]


def test_detail_retains_bounded_fields_and_omits_advisory_body() -> None:
    detail = json.loads(
        Path("tests/fixtures/osv-detail.json").read_text(encoding="utf-8")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": detail["id"]}]}]}
            )
        return httpx.Response(200, json=detail)

    advisory = (
        _client(httpx.MockTransport(handler))
        .query_packages({"demo": snapshot()}, observed_at=NOW)
        .vulnerabilities["demo"][0]
    )
    assert advisory.id == "GHSA-test-0000"
    assert advisory.severity_label == "critical"
    assert "summary" not in advisory.model_dump()
    assert "details" not in advisory.model_dump()


def test_detail_failure_marks_package_incomplete() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": "GHSA-broken"}]}]}
            )
        return httpx.Response(503)

    result = _client(httpx.MockTransport(handler)).query_packages(
        {"demo": snapshot()}, observed_at=NOW
    )
    assert result.incomplete_packages == {"demo"}
    assert result.errors[0].source == "osv"


def test_mismatched_result_count_is_incomplete_not_empty() -> None:
    client = _client(
        httpx.MockTransport(lambda _request: httpx.Response(200, json={"results": []}))
    )
    result = client.query_packages({"demo": snapshot()}, observed_at=NOW)
    assert result.incomplete_packages == {"demo"}
    assert result.errors[0].code == "malformed_response"
