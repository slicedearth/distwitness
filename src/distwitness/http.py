"""Bounded HTTPS client for fixed, allowlisted public APIs."""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from types import TracebackType
from typing import Any, Final, Self
from urllib.parse import urljoin, urlsplit

import httpx

from distwitness.logging import safe_log_value

ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({"pypi.org", "api.osv.dev"})
REDacted_HEADERS: Final[frozenset[str]] = frozenset(
    {"authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key"}
)
REDIRECT_STATUSES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})
HTTP_OK: Final = 200
HTTP_NOT_MODIFIED: Final = 304
HTTP_SERVER_ERROR: Final = 500
MAX_REQUEST_INTERVAL_SECONDS: Final = 5.0


class HttpSafetyError(ValueError):
    """Raised before an unsafe target can be requested."""


class SourceRequestError(RuntimeError):
    """Structured transport/status/content failure."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        url: str,
        retryable: bool,
        status_code: int | None = None,
    ) -> None:
        super().__init__(safe_log_value(message))
        self.code = code
        self.url = url
        self.retryable = retryable
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class JsonResponse:
    """A bounded decoded response and the non-sensitive metadata callers need."""

    status_code: int
    url: str
    data: Any | None
    etag: str | None
    last_modified: str | None


@dataclass(frozen=True, slots=True)
class _MemoryCacheEntry:
    data: Any
    etag: str | None
    last_modified: str | None


@dataclass(frozen=True, slots=True)
class _BufferedResponse:
    """Decoded response bytes detached from the live transport stream."""

    status_code: int
    headers: httpx.Headers
    content: bytes


def redact_headers(headers: httpx.Headers | dict[str, str]) -> dict[str, str]:
    """Return a log-safe copy of headers with credential-bearing fields redacted."""

    return {
        str(name): "[REDACTED]" if str(name).lower() in REDacted_HEADERS else value
        for name, value in headers.items()
    }


class BoundedHttpClient:
    """HTTP client with strict destinations, sizes, redirects, and retries."""

    def __init__(
        self,
        *,
        user_agent: str,
        max_response_bytes: int = 4 * 1024 * 1024,
        max_retries: int = 2,
        max_redirects: int = 2,
        no_cache: bool = False,
        client: httpx.Client | None = None,
        sleep: Any = time.sleep,
        jitter: Any | None = None,
        clock: Any = time.monotonic,
        min_request_interval: float = 0.05,
    ) -> None:
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        if not 0 <= min_request_interval <= MAX_REQUEST_INTERVAL_SECONDS:
            raise ValueError("min_request_interval must be between 0 and 5 seconds")
        self.max_response_bytes = max_response_bytes
        self.max_retries = max_retries
        self.max_redirects = max_redirects
        self.no_cache = no_cache
        self._sleep = sleep
        self._jitter = jitter or random.SystemRandom().uniform
        self._clock = clock
        self._min_request_interval = min_request_interval
        self._last_request_at: float | None = None
        self._cache: dict[str, _MemoryCacheEntry] = {}
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(connect=5, read=15, write=10, pool=5),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "User-Agent": user_agent,
            },
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the internally owned transport."""

        if self._owns_client:
            self._client.close()

    @staticmethod
    def validate_url(url: str) -> None:
        """Reject any target outside the fixed HTTPS API boundary."""

        parsed = urlsplit(url)
        if parsed.scheme != "https":
            raise HttpSafetyError("only HTTPS source URLs are allowed")
        if parsed.username or parsed.password:
            raise HttpSafetyError("credentials are not allowed in source URLs")
        host = (parsed.hostname or "").lower().rstrip(".")
        if host not in ALLOWED_HOSTS:
            raise HttpSafetyError(
                f"source host is not allowlisted: {host or '<empty>'}"
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise HttpSafetyError("invalid source URL port") from exc
        if port not in {None, 443}:
            raise HttpSafetyError("only the default HTTPS port is allowed")

    def request_json(  # noqa: PLR0912 - explicit HTTP state handling is auditable.
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        accepted_statuses: frozenset[int] = frozenset({200}),
        accept: str = "application/json",
        max_response_bytes: int | None = None,
    ) -> JsonResponse:
        """Fetch and decode bounded JSON, retrying only transient failures."""

        method = method.upper()
        if method not in {"GET", "POST"}:
            raise HttpSafetyError("only GET and POST are supported")
        self.validate_url(url)
        body_key = (
            json.dumps(json_body, sort_keys=True, separators=(",", ":"))
            if json_body is not None
            else ""
        )
        cache_key = f"{method} {url} {body_key}"
        cache_entry = None if self.no_cache else self._cache.get(cache_key)
        headers = {"Accept": accept}
        if method == "GET" and cache_entry:
            if cache_entry.etag:
                headers["If-None-Match"] = cache_entry.etag
            if cache_entry.last_modified:
                headers["If-Modified-Since"] = cache_entry.last_modified

        current_url = url
        redirects = 0
        for attempt in range(self.max_retries + 1):
            try:
                response = self._send(
                    method,
                    current_url,
                    headers=headers,
                    json_body=json_body,
                    max_response_bytes=max_response_bytes or self.max_response_bytes,
                )
            except httpx.RequestError as exc:
                if attempt >= self.max_retries:
                    raise SourceRequestError(
                        code="request_failed",
                        message=f"request failed: {exc.__class__.__name__}",
                        url=current_url,
                        retryable=True,
                    ) from exc
                self._backoff(attempt, None)
                continue

            if response.status_code in REDIRECT_STATUSES:
                location = response.headers.get("location")
                if not location:
                    raise SourceRequestError(
                        code="invalid_redirect",
                        message="redirect response omitted Location",
                        url=current_url,
                        retryable=False,
                        status_code=response.status_code,
                    )
                redirects += 1
                if redirects > self.max_redirects:
                    raise SourceRequestError(
                        code="redirect_limit",
                        message="redirect limit exceeded",
                        url=current_url,
                        retryable=False,
                        status_code=response.status_code,
                    )
                current_url = urljoin(current_url, location)
                self.validate_url(current_url)
                continue

            if response.status_code == HTTP_NOT_MODIFIED and cache_entry is not None:
                return JsonResponse(
                    status_code=HTTP_OK,
                    url=current_url,
                    data=cache_entry.data,
                    etag=cache_entry.etag,
                    last_modified=cache_entry.last_modified,
                )

            if response.status_code in {429, 500, 502, 503, 504}:
                if attempt < self.max_retries:
                    self._backoff(attempt, response.headers.get("retry-after"))
                    continue
                raise SourceRequestError(
                    code=f"http_{response.status_code}",
                    message=f"source returned HTTP {response.status_code}",
                    url=current_url,
                    retryable=True,
                    status_code=response.status_code,
                )

            if response.status_code not in accepted_statuses:
                raise SourceRequestError(
                    code=f"http_{response.status_code}",
                    message=f"source returned HTTP {response.status_code}",
                    url=current_url,
                    retryable=response.status_code >= HTTP_SERVER_ERROR,
                    status_code=response.status_code,
                )

            if (
                response.status_code in accepted_statuses
                and response.status_code != HTTP_OK
            ):
                return JsonResponse(
                    status_code=response.status_code,
                    url=current_url,
                    data=None,
                    etag=response.headers.get("etag"),
                    last_modified=response.headers.get("last-modified"),
                )

            try:
                data = json.loads(response.content)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceRequestError(
                    code="malformed_json",
                    message="source returned malformed JSON",
                    url=current_url,
                    retryable=False,
                    status_code=response.status_code,
                ) from exc
            result = JsonResponse(
                status_code=response.status_code,
                url=current_url,
                data=data,
                etag=response.headers.get("etag"),
                last_modified=response.headers.get("last-modified"),
            )
            if not self.no_cache and method == "GET":
                self._cache[cache_key] = _MemoryCacheEntry(
                    data=data,
                    etag=result.etag,
                    last_modified=result.last_modified,
                )
            return result

        raise AssertionError("retry loop exited unexpectedly")

    def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        json_body: dict[str, Any] | None,
        max_response_bytes: int,
    ) -> _BufferedResponse:
        self._pace()
        with self._client.stream(
            method,
            url,
            headers=headers,
            json=json_body,
        ) as response:
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = 0
                if declared_size > max_response_bytes:
                    raise SourceRequestError(
                        code="response_too_large",
                        message="declared response size exceeds configured limit",
                        url=url,
                        retryable=False,
                        status_code=response.status_code,
                    )
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_response_bytes:
                    raise SourceRequestError(
                        code="response_too_large",
                        message="response exceeds configured byte limit",
                        url=url,
                        retryable=False,
                        status_code=response.status_code,
                    )
            return _BufferedResponse(
                status_code=response.status_code,
                headers=response.headers,
                content=bytes(body),
            )

    def _pace(self) -> None:
        """Keep request starts sequential and at least a small interval apart."""

        now = float(self._clock())
        if self._last_request_at is not None:
            remaining = self._min_request_interval - (now - self._last_request_at)
            if remaining > 0:
                self._sleep(remaining)
                now = float(self._clock())
        self._last_request_at = now

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay = _retry_after_seconds(retry_after)
        if delay is None:
            delay = min(8.0, 0.5 * (2**attempt)) + float(self._jitter(0, 0.25))
        self._sleep(min(delay, 15.0))


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, min(float(value), 15.0))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return max(0.0, min((parsed.timestamp() - time.time()), 15.0))
