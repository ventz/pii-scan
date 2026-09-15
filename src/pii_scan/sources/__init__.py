"""Sources enumerate files to scan. Local filesystem and git diff today; Graph (SharePoint) planned."""

from .base import FileRef, ReadError, Source

__all__ = ["FileRef", "ReadError", "Source"]
