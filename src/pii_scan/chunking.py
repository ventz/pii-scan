"""Split text into API-sized windows with exact character offsets and overlap.

Offsets returned by detectors are character offsets into the chunk. Services disagree on whether
a "character" is a Unicode code point or a UTF-16 code unit; the two only differ for astral
characters (emoji, some CJK) and lone surrogates. `api_safe` replaces each of those with a single
U+FFFD, so both interpretations produce identical offsets that map 1:1 onto the original string.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

# Astral-plane code points and lone surrogates (from surrogateescape decoding).
_AMBIGUOUS = re.compile("[\U00010000-\U0010ffff\ud800-\udfff]")
_BREAK_NEWLINE = "\n"


@dataclass(frozen=True, slots=True)
class Chunk:
    start: int  # character offset of text[0] in the full document
    text: str


def api_safe(text: str) -> str:
    """Same length as `text`, valid UTF-8, and code-point offsets == UTF-16 offsets."""
    if text.isascii():
        return text
    return _AMBIGUOUS.sub("�", text)


def _utf8_len(s: str) -> int:
    return len(s.encode("utf-8", errors="surrogatepass"))


def chunks(text: str, max_bytes: int, overlap_chars: int = 1024) -> Iterator[Chunk]:
    """Yield windows of at most `max_bytes` UTF-8 bytes, preferring newline then whitespace breaks.

    Consecutive windows overlap by up to `overlap_chars` so an entity straddling a boundary is
    fully contained in at least one window (when shorter than the overlap).
    """
    if max_bytes < 64:
        raise ValueError("max_bytes must be at least 64")
    n = len(text)
    overlap_chars = max(0, min(overlap_chars, max_bytes // 4))
    start = 0
    while start < n:
        end = min(n, start + max_bytes)  # one char is at least one byte
        size = _utf8_len(text[start:end])
        while size > max_bytes:
            # shrink proportionally, then re-measure; converges in a few iterations
            end = start + max(1, int((end - start) * max_bytes / size * 0.97))
            size = _utf8_len(text[start:end])
        if end < n:
            end = _soft_break(text, start, end)
        yield Chunk(start, text[start:end])
        if end >= n:
            return
        nxt = end - overlap_chars
        start = nxt if nxt > start else end


def _soft_break(text: str, start: int, end: int) -> int:
    """Move `end` back to just after a newline (or whitespace) in the last half of the window."""
    floor = start + (end - start) // 2
    cut = text.rfind(_BREAK_NEWLINE, floor, end)
    if cut != -1:
        return cut + 1
    for i in range(end - 1, floor - 1, -1):
        if text[i].isspace():
            return i + 1
    return end


class LineIndex:
    """Map character offsets to 1-based (line, column)."""

    __slots__ = ("_starts",)

    def __init__(self, text: str) -> None:
        starts = [0]
        find = text.find
        i = find("\n")
        while i != -1:
            starts.append(i + 1)
            i = find("\n", i + 1)
        self._starts = starts

    def position(self, offset: int) -> tuple[int, int]:
        from bisect import bisect_right

        line = bisect_right(self._starts, offset)
        return line, offset - self._starts[line - 1] + 1
