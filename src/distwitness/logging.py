"""Log hardening for untrusted upstream strings."""

from __future__ import annotations

import logging
import re

_LOG_CONTROLS = re.compile(r"[\x00-\x1f\x7f]")
MAX_LOG_FIELD = 300


def safe_log_value(value: object, *, limit: int = MAX_LOG_FIELD) -> str:
    """Flatten control characters and bound an untrusted value for logs."""

    return _LOG_CONTROLS.sub(" ", str(value))[:limit]


def configure_logging(*, verbose: bool) -> None:
    """Configure concise process logging once at the CLI boundary."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.INFO if verbose else logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.INFO if verbose else logging.WARNING)
