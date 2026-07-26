from __future__ import annotations

import gzip

import httpx
import pytest

from distwitness.http import (
    BoundedHttpClient,
    HttpSafetyError,
    SourceRequestError,
    redact_headers,
)
from distwitness.logging import safe_log_value


def _client(
    handler: httpx.MockTransport,
    *,
    max_bytes: int = 1024,
    retries: int = 2,
    sleeps: list[float] | None = None,
) -> BoundedHttpClient:
    recorded_sleeps = sleeps if sleeps is not None else []
    return BoundedHttpClient(
        user_agent="DistWitness tests (+https://example.test)",
        max_response_bytes=max_bytes,
        max_retries=retries,
        client=httpx.Client(transport=handler),
        sleep=recorded_sleeps.append,
        jitter=lambda _start, _end: 0,
        min_request_interval=0,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://pypi.org/pypi/demo/json",
        "https://example.com/api",
        "https://user:pass@pypi.org/api",
        "https://pypi.org:444/api",
    ],
)
def test_disallowed_targets_are_rejected_before_request(url: str) -> None:
    client = _client(httpx.MockTransport(lambda _request: httpx.Response(200)))
    with pytest.raises(HttpSafetyError):
        client.request_json("GET", url)


def test_disallowed_redirect_is_rejected() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            302, headers={"Location": "https://example.com/private"}
        )
    )
    with pytest.raises(HttpSafetyError):
        _client(transport).request_json("GET", "https://pypi.org/pypi/demo/json")


def test_allowed_redirect_is_bounded_and_decoded() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                302, headers={"Location": "https://pypi.org/pypi/demo2/json"}
            )
        return httpx.Response(200, json={"ok": True})

    result = _client(httpx.MockTransport(handler)).request_json(
        "GET", "https://pypi.org/pypi/demo/json"
    )
    assert result.data == {"ok": True}
    assert calls == 2


def test_declared_and_streamed_oversized_responses_are_rejected() -> None:
    declared = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"Content-Length": "10000"},
            content=b"{}",
        )
    )
    with pytest.raises(SourceRequestError, match="declared"):
        _client(declared, max_bytes=10).request_json(
            "GET", "https://pypi.org/pypi/demo/json"
        )
    streamed = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            stream=httpx.ByteStream(b'{"value":"' + b"x" * 100 + b'"}'),
        )
    )
    with pytest.raises(SourceRequestError, match="byte limit"):
        _client(streamed, max_bytes=20).request_json(
            "GET", "https://pypi.org/pypi/demo/json"
        )


def test_timeout_retries_then_succeeds() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json={"ok": True})

    result = _client(
        httpx.MockTransport(handler), retries=2, sleeps=sleeps
    ).request_json("GET", "https://api.osv.dev/v1/vulns/TEST")
    assert result.data == {"ok": True}
    assert calls == 3
    assert sleeps == [0.5, 1.0]


def test_request_starts_are_paced() -> None:
    current = [10.0]
    sleeps: list[float] = []

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        current[0] += delay

    client = BoundedHttpClient(
        user_agent="DistWitness tests (+https://example.test)",
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(200, json={"ok": True})
            )
        ),
        sleep=sleep,
        clock=lambda: current[0],
        min_request_interval=0.25,
    )
    client.request_json("GET", "https://pypi.org/pypi/one/json")
    current[0] += 0.1
    client.request_json("GET", "https://pypi.org/pypi/two/json")
    assert sleeps == pytest.approx([0.15])


def test_retry_after_is_capped_and_exhaustion_is_structured() -> None:
    sleeps: list[float] = []
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(429, headers={"Retry-After": "60"})
    )
    with pytest.raises(SourceRequestError) as captured:
        _client(transport, retries=1, sleeps=sleeps).request_json(
            "POST",
            "https://api.osv.dev/v1/querybatch",
            json_body={"queries": []},
        )
    assert captured.value.code == "http_429"
    assert captured.value.retryable is True
    assert sleeps == [15.0]


def test_conditional_cache_reuses_body_on_304() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, json={"value": 1}, headers={"ETag": '"one"'})
        assert request.headers["if-none-match"] == '"one"'
        return httpx.Response(304)

    client = _client(httpx.MockTransport(handler))
    first = client.request_json("GET", "https://pypi.org/pypi/demo/json")
    second = client.request_json("GET", "https://pypi.org/pypi/demo/json")
    assert first.data == second.data == {"value": 1}


def test_compressed_transport_body_is_decoded_once() -> None:
    payload = gzip.compress(b'{"value":1}')
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            content=payload,
        )
    )
    result = _client(transport).request_json("GET", "https://pypi.org/pypi/demo/json")
    assert result.data == {"value": 1}


def test_malformed_json_and_unexpected_status_fail() -> None:
    malformed = _client(
        httpx.MockTransport(lambda _request: httpx.Response(200, content=b"{"))
    )
    with pytest.raises(SourceRequestError) as captured:
        malformed.request_json("GET", "https://pypi.org/pypi/demo/json")
    assert captured.value.code == "malformed_json"
    missing = _client(httpx.MockTransport(lambda _request: httpx.Response(404)))
    with pytest.raises(SourceRequestError) as missing_error:
        missing.request_json("GET", "https://pypi.org/pypi/demo/json")
    assert missing_error.value.status_code == 404


def test_header_and_log_redaction() -> None:
    assert redact_headers(
        {"Authorization": "secret", "Cookie": "session", "Accept": "json"}
    ) == {
        "Authorization": "[REDACTED]",
        "Cookie": "[REDACTED]",
        "Accept": "json",
    }
    assert safe_log_value("bad\nFORGED\x1b[31m") == "bad FORGED [31m"
