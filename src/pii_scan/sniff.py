"""Decide whether bytes are text, and which encoding decodes them losslessly."""

from __future__ import annotations

import codecs

SNIFF_BYTES = 8192

_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),  # must precede UTF-16 LE (shares its first two bytes)
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

# C0 controls other than tab, LF, VT, FF, CR, and ESC are rare in real text files.
_ALLOWED_CONTROLS = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B}
_BAD_CONTROLS = bytes(b for b in range(0x20) if b not in _ALLOWED_CONTROLS)
_NOT_BAD_CONTROLS = bytes(b for b in range(256) if b not in _BAD_CONTROLS)


def _utf16_without_bom(sample: bytes) -> str | None:
    """Recognize BOM-less UTF-16 (common in Windows exports) by where the NUL bytes fall.

    Returns "utf-16le"/"utf-16be" (codec names without a BOM, so re-encoding adds none), or None.
    """
    n = len(sample) - len(sample) % 2
    if n < 8:
        return None
    even, odd = sample[0:n:2], sample[1:n:2]
    even_zero, odd_zero = even.count(0) / len(even), odd.count(0) / len(odd)
    for codec, zeros, other in (("utf-16le", odd_zero, even_zero), ("utf-16be", even_zero, odd_zero)):
        if zeros < 0.3 or other > 0.05:
            continue
        try:
            text = sample[: n - 2].decode(codec)  # drop the last unit in case a surrogate pair was cut
        except UnicodeDecodeError:
            continue
        controls = sum(1 for c in text if ord(c) < 32 and c not in "\t\n\r\x0b\x0c\x1b")
        if text and controls / len(text) <= 0.01:
            return codec
    return None


def bom_length(encoding: str) -> int:
    return {"utf-8-sig": 3, "utf-16-le": 2, "utf-16-be": 2, "utf-32-le": 4, "utf-32-be": 4}.get(encoding, 0)


def detect_encoding(sample: bytes, *, truncated: bool = False,
                    fallback: str | None = "cp1252") -> str | None:  # fmt: skip
    """Return a codec name for text, or None for binary.

    - A BOM wins.
    - Any NUL byte (without a BOM) means binary.
    - Strict UTF-8 means utf-8. When `truncated` (the sample is a prefix of a longer file), a
      multi-byte sequence cut at the very end of the sample is tolerated.
    - Otherwise, if `fallback` decodes it and control characters are rare, use the fallback
      (legacy Windows files are common on shares).
    """
    if not sample:
        return "utf-8"
    for bom, name in _BOMS:
        if sample.startswith(bom):
            return name
    if b"\x00" in sample:
        return _utf16_without_bom(sample)
    bad = len(sample.translate(None, delete=_NOT_BAD_CONTROLS))
    if bad / len(sample) > 0.01:
        return None
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    try:
        decoder.decode(sample, final=not truncated)
        return "utf-8"
    except UnicodeDecodeError:
        pass
    if fallback is None:
        return None
    try:
        sample.decode(fallback, errors="strict")
    except UnicodeDecodeError:
        return None
    return fallback


def _errors(codec: str) -> str:
    # surrogateescape round-trips undecodable bytes exactly for UTF-8 and single-byte codecs;
    # UTF-16/32 can't carry them, so invalid sequences there are replaced.
    return "surrogateescape" if codec in ("utf-8", "cp1252") else "replace"


def decode(data: bytes, encoding: str) -> str:
    """Decode losslessly: undecodable bytes become lone surrogates so `encode_like` round-trips exactly."""
    body = data[bom_length(encoding):]
    codec = {"utf-8-sig": "utf-8"}.get(encoding, encoding)
    return body.decode(codec, errors=_errors(codec))


def encode_like(text: str, encoding: str) -> bytes:
    """Inverse of `decode` (restores the BOM)."""
    codec = {"utf-8-sig": "utf-8"}.get(encoding, encoding)
    body = text.encode(codec, errors=_errors(codec))
    bom = next((b for b, name in _BOMS if name == encoding), b"")
    return bom + body
