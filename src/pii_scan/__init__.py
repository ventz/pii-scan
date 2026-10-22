"""pii-scan: find and mask PII and secrets in files, repositories, and file shares."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pii-scan")
except PackageNotFoundError:  # running from a source checkout without install
    __version__ = "1.1.1"

__all__ = ["__version__"]
