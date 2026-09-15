"""Layered AWS detection.

    regex (always, local, free)  ->  contains (screen)  ->  guardrails (detect)  ->  detect (detect)

Each AWS layer runs only where the previous AWS layer found something:
- a screen layer (contains) passes a chunk on only if it reports a relevant entity type
- a detector layer produces spans; a following detector runs only on chunks where it found spans
Spans from all detector layers are unioned, so a later layer can only add coverage.
"""

from __future__ import annotations

from collections.abc import Sequence
from concurrent.futures import Executor

from .chunking import api_safe, chunks
from .detectors.aws import ComprehendDetector, ContainsScreen, GuardrailsDetector
from .models import Span

OVERLAP_CHARS = 1024

Layer = ContainsScreen | GuardrailsDetector | ComprehendDetector


def _shift(spans: list[Span], offset: int) -> list[Span]:
    return [Span(s.start + offset, s.end + offset, s.type, s.score, s.detector, s.rule) for s in spans]


def _run(text: str, layers: Sequence[Layer], idx: int) -> list[Span]:
    """Spans for `text` (offsets relative to `text`) from layers[idx:]."""
    if idx >= len(layers):
        return []
    layer = layers[idx]
    out: list[Span] = []
    for ch in chunks(text, layer.max_bytes, OVERLAP_CHARS):
        if isinstance(layer, ContainsScreen):
            if layer.screen(ch.text):
                out.extend(_shift(_run(ch.text, layers, idx + 1), ch.start))
            continue
        found = layer.detect(ch.text)
        out.extend(_shift(found, ch.start))
        if found and idx + 1 < len(layers):
            out.extend(_shift(_run(ch.text, layers, idx + 1), ch.start))
    return out


def detect_remote(text: str, layers: Sequence[Layer], executor: Executor | None) -> list[Span]:
    """Run the layer chain over a whole document.

    The first layer's chunks run concurrently on `executor` (the API pool). Any DetectorError
    propagates, so a partially analyzed document is never reported clean.
    """
    if not layers or not text:
        return []
    safe = api_safe(text)
    first = layers[0]
    top = list(chunks(safe, first.max_bytes, OVERLAP_CHARS))
    if executor is None or len(top) == 1:
        return _run(safe, layers, 0)
    futures = [executor.submit(_run_single, c.text, c.start, layers) for c in top]
    out: list[Span] = []
    for fut in futures:
        out.extend(fut.result())  # re-raises DetectorError
    return out


def _run_single(text: str, offset: int, layers: Sequence[Layer]) -> list[Span]:
    layer = layers[0]
    if isinstance(layer, ContainsScreen):
        return _shift(_run(text, layers, 1), offset) if layer.screen(text) else []
    found = layer.detect(text)
    spans = _shift(found, offset)
    if found and len(layers) > 1:
        spans.extend(_shift(_run(text, layers, 1), offset))
    return spans
