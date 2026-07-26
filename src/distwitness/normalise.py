"""Canonicalisation helpers for hostile and unordered source metadata."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from urllib.parse import SplitResult, urlsplit, urlunsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
MAX_TEXT_LENGTH = 512
HTTP_PORT = 80
HTTPS_PORT = 443


class NormalisationError(ValueError):
    """Raised when a value cannot be safely represented."""


def normalise_package_name(value: str) -> str:
    """Validate a distribution name, then apply Python canonical naming."""

    if not isinstance(value, str) or not _PACKAGE_NAME.fullmatch(value):
        raise NormalisationError(f"invalid Python package name: {value!r}")
    return str(canonicalize_name(value))


def bounded_text(value: object, *, limit: int = MAX_TEXT_LENGTH) -> str | None:
    """Return a trimmed, control-free bounded string or ``None``."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise NormalisationError("expected a string or null")
    cleaned = _CONTROL_CHARS.sub(" ", value).strip()
    return cleaned[:limit]


def normalise_url(value: object) -> str | None:
    """Conservatively normalise a public HTTP(S) URL for output."""

    text = bounded_text(value)
    if not text:
        return None
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname or parsed.username or parsed.password:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower().rstrip(".")
    if not host or any(char.isspace() for char in host):
        return None
    netloc = host
    if port is not None:
        default = (parsed.scheme.lower() == "http" and port == HTTP_PORT) or (
            parsed.scheme.lower() == "https" and port == HTTPS_PORT
        )
        if not default:
            netloc = f"{host}:{port}"
    path = parsed.path or "/"
    normalised = SplitResult(
        scheme=parsed.scheme.lower(),
        netloc=netloc,
        path=path,
        query=parsed.query,
        fragment="",
    )
    return urlunsplit(normalised)


def normalise_urls(value: object) -> dict[str, str]:
    """Normalise, bound, sort, and deduplicate a project-URL mapping."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise NormalisationError("project_urls must be an object")
    output: dict[str, str] = {}
    for raw_key, raw_url in value.items():
        key = bounded_text(raw_key, limit=80)
        url = normalise_url(raw_url)
        if key and url:
            output[key] = url
    return dict(sorted(output.items(), key=lambda item: (item[0].casefold(), item[1])))


def normalise_string_list(
    value: object,
    *,
    item_limit: int = MAX_TEXT_LENGTH,
    max_items: int = 500,
) -> tuple[str, ...]:
    """Return a deterministic tuple from an unordered string collection."""

    if value is None:
        return ()
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise NormalisationError("expected a list of strings")
    if len(value) > max_items:
        raise NormalisationError(f"list exceeds {max_items} items")
    items = {text for item in value if (text := bounded_text(item, limit=item_limit))}
    return tuple(sorted(items, key=lambda item: (item.casefold(), item)))


def normalise_requirements(value: object) -> tuple[str, ...]:
    """Parse and canonically render dependency declarations without weakening specs."""

    raw_items = normalise_string_list(value, item_limit=1000, max_items=500)
    rendered: set[str] = set()
    for raw in raw_items:
        try:
            requirement = Requirement(raw)
        except InvalidRequirement as exc:
            raise NormalisationError(f"invalid requires_dist value: {raw!r}") from exc
        requirement.name = normalise_package_name(requirement.name)
        rendered.add(str(requirement))
    return tuple(sorted(rendered, key=lambda item: (item.casefold(), item)))


def licensing_classifiers(values: Iterable[str]) -> tuple[str, ...]:
    """Retain only bounded Trove classifiers relevant to licensing."""

    return tuple(
        sorted(
            {
                value
                for value in values
                if value.startswith("License ::") and len(value) <= MAX_TEXT_LENGTH
            },
            key=lambda item: (item.casefold(), item),
        )
    )
