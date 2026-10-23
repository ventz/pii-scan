"""Masking: turn merged spans into replacement text, previews, fingerprints, and safe output files."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path

from .models import Span
from .private import WINDOWS, create_private_file, is_link, make_private_dirs, windows_name_problem
from .spans import MergedSpan


class MaskStyle(StrEnum):
    LABEL = "label"  # [SSN]
    GENERIC = "generic"  # [REDACTED]
    STARS = "stars"  # *********** (same length, keeps line structure)
    PARTIAL = "partial"  # *******6789 (keeps last 4 of values 8+ chars long)
    HASH = "hash"  # [SSN:3f9a1c0b] deterministic pseudonym (keyed HMAC)

    def __str__(self) -> str:
        return self.value


class Masker:
    def __init__(self, style: MaskStyle = MaskStyle.LABEL, key: bytes | None = None) -> None:
        self.style = style
        # Per-run random key unless one is supplied: fingerprints are stable within a run (and
        # across runs when PII_SCAN_HMAC_KEY is set) but cannot be reversed or brute-forced
        # offline without the key.
        self.key = key or secrets.token_bytes(32)

    def fingerprint(self, value: str) -> str:
        digest = hmac.new(self.key, value.encode("utf-8", "surrogatepass"), hashlib.sha256)
        return digest.hexdigest()[:16]

    def replacement(self, value: str, entity_type: str) -> str:
        style = self.style
        if style is MaskStyle.LABEL:
            return f"[{entity_type}]"
        if style is MaskStyle.GENERIC:
            return "[REDACTED]"
        if style is MaskStyle.STARS:
            return _stars(value)
        if style is MaskStyle.PARTIAL:
            if len(value) >= 8:
                return _stars(value[:-4]) + value[-4:]
            return _stars(value)
        return f"[{entity_type}:{self.fingerprint(value)[:12]}]"  # 48 bits: collisions stay rare at share scale

    def apply(self, text: str, regions: list[MergedSpan]) -> str:
        """Single forward pass over disjoint, sorted regions (see spans.merge)."""
        if not regions:
            return text
        out: list[str] = []
        pos = 0
        for r in regions:
            if r.start < pos:
                raise ValueError("regions must be disjoint and sorted")
            out.append(text[pos:r.start])
            out.append(self.replacement(text[r.start:r.end], r.type))
            pos = r.end
        out.append(text[pos:])
        return "".join(out)


LEAK_CHECK_MIN_CHARS = 6


def verify_masked(text: str, spans: Iterable[Span], masked: str) -> None:
    """Raise if any detected value of LEAK_CHECK_MIN_CHARS+ characters still appears in the output.

    Checks each detection on its own, not the merged regions: a value inside a larger merged region
    can still appear unmasked elsewhere in the file. Shorter values are skipped: they also occur by
    chance in unrelated text.
    """
    values = {text[s.start:s.end] for s in spans if s.end - s.start >= LEAK_CHECK_MIN_CHARS}
    leaked = sum(1 for v in values if v and v in masked)
    if leaked:
        raise ValueError(f"verification failed: {leaked} value(s) still present after masking")


def _stars(value: str) -> str:
    # Keep line breaks so line numbers in masked copies still match the original.
    return "".join(c if c in "\r\n" else "*" for c in value)


def preview(value: str, entity_type: str, *, reveal: bool = False) -> str:
    """A speakable, non-sensitive description of a value for reports and logs."""
    if reveal:
        return value
    return f"[{entity_type}, {len(value)} chars]"


def write_atomic(dest: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write via a same-directory temp file, fsync, then rename. Never follows a link at dest.

    The temp file is made owner-only before any data is written; the rename keeps that.
    """
    make_private_dirs(dest.parent)
    with contextlib.suppress(FileNotFoundError):
        if is_link(os.lstat(dest)):
            raise OSError(f"refusing to write through a symlink or junction: {dest}")
    while True:
        tmp = str(dest.parent / f".pii-scan-{secrets.token_hex(8)}")
        try:
            fd = create_private_file(tmp, mode)  # private before any data is written
            break
        except FileExistsError:
            continue
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def safe_output_path(out_root: Path, relpath: str) -> Path:
    """Place `relpath` under `out_root`, rejecting `..`, absolute paths, and symlinked parents.

    The final component is deliberately not resolved, so `write_atomic` can refuse a symlink there.
    """
    root = out_root.resolve()
    norm = os.path.normpath(relpath)
    if os.path.isabs(norm) or norm == os.pardir or norm.startswith(os.pardir + os.sep):
        raise ValueError(f"output path escapes output directory: {relpath}")
    if WINDOWS:
        for part in Path(norm).parts:
            problem = windows_name_problem(part)
            if problem:
                raise ValueError(f"output path component {part!r} {problem}: {relpath}")
    candidate = root / norm
    existing = candidate.parent
    while not existing.exists():
        existing = existing.parent
    real_parent = existing.resolve()
    # the deepest existing directory must be the root, inside it, or (root not created yet) above it
    if real_parent != root and root not in real_parent.parents and real_parent not in root.parents:
        raise ValueError(f"output path escapes output directory through a symlink: {relpath}")
    return candidate
