from __future__ import annotations

from typing import Protocol

from ..models import Span


class DetectorError(Exception):
    """A detector could not analyze the text. The file must be reported NOT_SCANNED, never clean."""

    def __init__(self, message: str, *, fatal: bool = False) -> None:
        super().__init__(message)
        self.fatal = fatal  # True for errors that will hit every file (credentials, access denied)


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> list[Span]:
        """Return spans with offsets relative to `text`. Raise DetectorError on any failure."""
        ...
