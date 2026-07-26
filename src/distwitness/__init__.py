"""DistWitness release-change monitor."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("distwitness")
except PackageNotFoundError:
    __version__ = "0.4.0"

__all__ = ["__version__"]
