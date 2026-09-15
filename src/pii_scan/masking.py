"""Masking: turn merged spans into replacement text, previews, fingerprints, and safe output files."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
import tempfile
from enum import StrEnum
from pathlib import Path

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
        return f"[{entity_type}:{self.fingerprint(value)[:8]}]"

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


def _stars(value: str) -> str:
    # Keep line breaks so line numbers in masked copies still match the original.
    return "".join(c if c in "\r\n" else "*" for c in value)


def preview(value: str, entity_type: str, *, reveal: bool = False) -> str:
    """A speakable, non-sensitive description of a value for reports and logs."""
    if reveal:
        return value
    return f"[{entity_type}, {len(value)} chars]"


def write_atomic(dest: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write via a same-directory temp file, fsync, then rename. Never follows a symlink at dest."""
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if dest.is_symlink():
        raise OSError(f"refusing to write through symlink: {dest}")
    fd, tmp = tempfile.mkstemp(prefix=".pii-scan-", dir=dest.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def safe_output_path(out_root: Path, relpath: str) -> Path:
    """Resolve `relpath` under `out_root`, rejecting anything that escapes it."""
    root = out_root.resolve()
    candidate = (root / relpath).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"output path escapes output directory: {relpath}")
    return candidate
