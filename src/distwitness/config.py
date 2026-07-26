"""Strict, safe watchlist configuration loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from distwitness.models import WatchlistConfig

HARD_MAX_PACKAGES = 100


class ConfigError(ValueError):
    """Raised when a watchlist is unsafe or invalid."""


def load_config(path: Path) -> WatchlistConfig:
    """Load a YAML watchlist with safe parsing and strict schema validation."""

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read configuration: {path}") from exc
    try:
        data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be an object")
    try:
        config = WatchlistConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"configuration validation failed:\n{exc}") from exc

    package_count = len(config.packages)
    if package_count == 0:
        raise ConfigError("at least one package is required")
    if package_count > HARD_MAX_PACKAGES:
        raise ConfigError(f"package count exceeds hard maximum {HARD_MAX_PACKAGES}")
    if package_count > config.project.max_packages:
        raise ConfigError(
            f"package count {package_count} exceeds configured max_packages "
            f"{config.project.max_packages}"
        )
    names = [package.normalised_name for package in config.packages]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ConfigError(
            "duplicate normalised package names: " + ", ".join(duplicates)
        )
    return config
