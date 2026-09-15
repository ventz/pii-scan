from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class FileRef:
    """One object to scan. `error` is set when enumeration itself failed for this entry."""

    path: str  # identity: absolute path for local files, URI for remote sources
    relpath: str  # path relative to the scan root, used for output trees and excludes
    size: int = -1
    mtime_ns: int = 0
    excluded: str = ""  # non-empty: skipped by policy, value is the reason
    error: str = ""
    source: str = "fs"  # "fs" | "git" | later "graph"
    etag: str = ""  # change token for remote sources (Graph cTag/eTag)
    root: str = ""  # real path the file must stay under when read (guards parent-directory symlink swaps)


class ReadError(Exception):
    """The object could not be read safely. `reason` is a short machine-friendly code."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class Source(Protocol):
    """Contract every source (local fs, git, and later Microsoft Graph) implements."""

    def __iter__(self) -> Iterator[FileRef]: ...

    def read(self, ref: FileRef, max_bytes: int) -> bytes:
        """Return the full content (at most `max_bytes`) or raise ReadError."""
        ...
