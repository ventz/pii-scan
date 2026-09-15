"""Span normalization: dedupe detector output and merge overlaps before reporting or masking."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .models import Severity, Span


@dataclass(frozen=True, slots=True)
class MergedSpan:
    """A disjoint region to mask. `type` is the most severe member type; `members` keeps all hits."""

    start: int
    end: int
    type: str
    members: tuple[Span, ...]


def dedupe(spans: Iterable[Span]) -> list[Span]:
    """Collapse duplicates from overlapping chunks and multiple detectors.

    - identical (start, end, type): keep the best score
    - a span contained in another span of the same type (a truncated hit at a chunk edge): drop it
    """
    best: dict[tuple[int, int, str], Span] = {}
    for s in spans:
        if s.end <= s.start:
            continue
        key = (s.start, s.end, s.type)
        cur = best.get(key)
        if cur is None or s.score > cur.score:
            best[key] = s
    ordered = sorted(best.values(), key=lambda s: (s.type, s.start, -s.end))
    kept: list[Span] = []
    reach: dict[str, int] = {}  # per type: furthest end among kept spans (sorted by start)
    for s in ordered:
        if s.end <= reach.get(s.type, -1):
            continue  # fully inside an earlier span of the same type
        kept.append(s)
        reach[s.type] = max(reach.get(s.type, -1), s.end)
    return sorted(kept, key=lambda s: (s.start, -s.end, s.type))


def merge(spans: Iterable[Span], severity_of: Callable[[str], Severity]) -> list[MergedSpan]:
    """Union overlapping or touching spans into disjoint regions.

    The merged label is the member with the highest severity, then the longest span, then the
    highest score, so a secret nested inside a NAME span is labeled as the secret.
    """
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    out: list[MergedSpan] = []
    group: list[Span] = []
    g_start = g_end = 0
    for s in ordered:
        if s.end <= s.start:
            continue
        if group and s.start <= g_end:
            group.append(s)
            g_end = max(g_end, s.end)
            continue
        if group:
            out.append(_close(group, g_start, g_end, severity_of))
        group, g_start, g_end = [s], s.start, s.end
    if group:
        out.append(_close(group, g_start, g_end, severity_of))
    return out


def _close(group: list[Span], start: int, end: int, severity_of: Callable[[str], Severity]) -> MergedSpan:
    lead = max(group, key=lambda s: (severity_of(s.type), s.end - s.start, s.score))
    return MergedSpan(start, end, lead.type, tuple(group))
