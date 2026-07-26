from __future__ import annotations

from pathlib import Path

import pytest

from distwitness.config import ConfigError, load_config
from distwitness.normalise import (
    NormalisationError,
    bounded_text,
    normalise_package_name,
    normalise_requirements,
    normalise_url,
    normalise_urls,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("PyYAML", "pyyaml"),
        ("zope.interface", "zope-interface"),
        ("demo_package", "demo-package"),
        ("Demo---Package", "demo-package"),
    ],
)
def test_package_name_normalisation(raw: str, expected: str) -> None:
    assert normalise_package_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "../demo", "demo/name", "demo name", "$(touch bad)", "-demo", "demo-"],
)
def test_invalid_package_names_are_rejected(raw: str) -> None:
    with pytest.raises(NormalisationError):
        normalise_package_name(raw)


def test_requirements_preserve_material_specifiers_and_sort() -> None:
    assert normalise_requirements(
        ["Requests>=2; python_version >= '3.12'", "httpx[http2]~=0.28"]
    ) == (
        "httpx[http2]~=0.28",
        'requests>=2; python_version >= "3.12"',
    )


def test_invalid_requirement_is_rejected() -> None:
    with pytest.raises(NormalisationError, match="requires_dist"):
        normalise_requirements(["demo >>> 1"])


def test_urls_are_conservative_and_deterministic() -> None:
    assert normalise_url("HTTPS://Example.COM:443/path#fragment") == (
        "https://example.com/path"
    )
    assert normalise_url("javascript:alert(1)") is None
    assert normalise_url("https://user:pass@example.com/") is None
    assert normalise_urls(
        {"Docs": "https://EXAMPLE.com/docs", "Bad": "file:///tmp/x"}
    ) == {"Docs": "https://example.com/docs"}


def test_bounded_text_flattens_log_controls() -> None:
    assert bounded_text("one\nTWO\x00three", limit=20) == "one TWO three"


def _write_config(path: Path, package_lines: str, project_extra: str = "") -> None:
    path.write_text(
        (
            "project:\n"
            "  title: Test\n"
            "  retention_days: 30\n"
            "  max_packages: 2\n"
            f"{project_extra}"
            "packages:\n"
            f"{package_lines}"
        ),
        encoding="utf-8",
    )


def test_valid_config_loads(tmp_path: Path) -> None:
    path = tmp_path / "watchlist.yml"
    _write_config(path, "  - name: Demo_Package\n  - name: httpx\n")
    config = load_config(path)
    assert [item.normalised_name for item in config.packages] == [
        "demo-package",
        "httpx",
    ]


def test_default_watchlist_is_bounded_and_role_diverse() -> None:
    config = load_config(Path("config/watchlist.yml"))
    names = {package.normalised_name for package in config.packages}

    assert len(names) == 25
    assert config.project.max_packages == 50
    assert {
        "httpx",
        "cryptography",
        "fastapi",
        "build",
        "pytest",
        "ruff",
    } <= names


def test_duplicate_normalised_names_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "watchlist.yml"
    _write_config(path, "  - name: Demo_Package\n  - name: demo-package\n")
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(path)


@pytest.mark.parametrize(
    "content",
    [
        "[]\n",
        "project: {}\npackages: []\n",
        "project:\n  title: Test\n  unknown: true\npackages:\n  - name: demo\n",
        (
            "project:\n  title: Test\n  max_packages: 1\npackages:\n"
            "  - name: one\n  - name: two\n"
        ),
        (
            "project:\n  title: Test\npackages:\n"
            "  - name: demo\n    endpoint: https://example.com\n"
        ),
    ],
)
def test_invalid_configurations_are_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "watchlist.yml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_unsafe_yaml_tag_is_not_executed(tmp_path: Path) -> None:
    path = tmp_path / "watchlist.yml"
    path.write_text("!!python/object/apply:os.system ['echo bad']\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(path)
