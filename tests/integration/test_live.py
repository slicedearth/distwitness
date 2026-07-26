from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from distwitness.config import load_config
from distwitness.runner import collect


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("DISTWITNESS_LIVE_TEST") != "1",
    reason="set DISTWITNESS_LIVE_TEST=1 to opt in to one bounded live query",
)
def test_opt_in_live_query_is_bounded() -> None:
    """Contact documented APIs for the included watchlist only when opted in."""

    config = load_config(Path("config/watchlist.yml"))
    one_package = config.model_copy(update={"packages": config.packages[:1]})
    result = collect(one_package, now=datetime.now(UTC), no_cache=True)
    assert result.successful_packages == ("httpx",)
