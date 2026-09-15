import codecs

import pytest

from pii_scan.chunking import LineIndex, api_safe, chunks
from pii_scan.entities import DEFAULT_SEVERITY, validate_type_names
from pii_scan.masking import Masker, MaskStyle, safe_output_path
from pii_scan.models import Severity, Span
from pii_scan.sniff import decode, detect_encoding, encode_like
from pii_scan.spans import dedupe, merge


def sev(t: str) -> Severity:
    return DEFAULT_SEVERITY.get(t, Severity.HIGH)


# --- chunking -------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["a" * 5000, "é" * 3050, "😀x" * 900, "line\n" * 2000, ""])
@pytest.mark.parametrize("max_bytes", [64, 500, 4096])
def test_chunks_respect_byte_limit_and_cover_text(text, max_bytes):
    got = list(chunks(text, max_bytes, overlap_chars=16))
    covered = 0
    for c in got:
        assert len(c.text.encode("utf-8", "surrogatepass")) <= max_bytes
        assert text[c.start : c.start + len(c.text)] == c.text
        assert c.start <= covered  # no gaps
        covered = max(covered, c.start + len(c.text))
    assert covered == len(text)
    starts = [c.start for c in got]
    assert starts == sorted(set(starts))  # strictly increasing: always makes progress


def test_boundary_entity_is_whole_in_some_chunk():
    ssn = "123-45-6789"
    for pad in range(480, 520):
        text = "x" * pad + ssn + "y" * 600
        pos = text.index(ssn)
        assert any(
            c.start <= pos and pos + len(ssn) <= c.start + len(c.text)
            for c in chunks(text, 512, overlap_chars=64)
        )


def test_api_safe_keeps_length_and_is_valid_utf8():
    raw = "hi 😀 there \udcff end"
    safe = api_safe(raw)
    assert len(safe) == len(raw)
    safe.encode("utf-8")  # no lone surrogates
    assert len(safe.encode("utf-16-le")) // 2 == len(safe)  # UTF-16 units == code points


def test_line_index():
    idx = LineIndex("ab\ncd\n\nef")
    assert idx.position(0) == (1, 1)
    assert idx.position(4) == (2, 2)
    assert idx.position(7) == (4, 1)


# --- spans + masking ------------------------------------------------------------------------


def test_overlap_regression_call_name_ow():
    text = "Call John Smith at 555-123-4567 now"
    spans = [
        Span(5, 15, "NAME", 0.99, "comprehend"),
        Span(10, 31, "CUSTOM:x", 1.0, "regex"),
    ]
    regions = merge(dedupe(spans), sev)
    assert [(r.start, r.end) for r in regions] == [(5, 31)]
    out = Masker(MaskStyle.LABEL).apply(text, regions)
    assert out == "Call [CUSTOM:x] now"
    assert "4567" not in out and "Smith" not in out


def test_merge_prefers_most_severe_label():
    spans = [Span(0, 20, "NAME", 0.9, "comprehend"), Span(5, 9, "PASSWORD", 1.0, "regex")]
    (region,) = merge(spans, sev)
    assert region.type == "PASSWORD" and (region.start, region.end) == (0, 20)


def test_dedupe_keeps_best_score():
    spans = [Span(1, 4, "SSN", 0.5, "comprehend"), Span(1, 4, "SSN", 0.9, "comprehend")]
    assert [s.score for s in dedupe(spans)] == [0.9]


@pytest.mark.parametrize(
    "style,expected",
    [
        (MaskStyle.LABEL, "id [SSN] ok"),
        (MaskStyle.GENERIC, "id [REDACTED] ok"),
        (MaskStyle.STARS, "id *********** ok"),
        (MaskStyle.PARTIAL, "id *******6789 ok"),
    ],
)
def test_mask_styles(style, expected):
    text = "id 123-45-6789 ok"
    regions = merge([Span(3, 14, "SSN", 1.0, "regex")], sev)
    assert Masker(style).apply(text, regions) == expected


def test_hash_style_is_deterministic_with_key():
    m = Masker(MaskStyle.HASH, key=b"k" * 32)
    assert m.replacement("a@b.com", "EMAIL") == m.replacement("a@b.com", "EMAIL")
    assert m.replacement("a@b.com", "EMAIL") != m.replacement("c@d.com", "EMAIL")


def test_safe_output_path_rejects_escape(tmp_path):
    assert safe_output_path(tmp_path, "a/b.txt") == (tmp_path / "a/b.txt").resolve()
    with pytest.raises(ValueError):
        safe_output_path(tmp_path, "../evil.txt")


# --- sniff ----------------------------------------------------------------------------------


def test_detect_encoding():
    assert detect_encoding("Привет мир".encode()) == "utf-8"
    assert detect_encoding("日本語".encode()[:-1], truncated=True) == "utf-8"  # prefix cut mid-char
    assert detect_encoding("日本語".encode()[:-1]) == "cp1252" or detect_encoding("日本語".encode()[:-1]) is None
    assert detect_encoding(codecs.BOM_UTF16_LE + "hi".encode("utf-16-le")) == "utf-16-le"
    assert detect_encoding(b"\x00\x01\x02binary") is None
    assert detect_encoding("café".encode("cp1252")) == "cp1252"
    assert detect_encoding(bytes(range(1, 32)) * 10) is None


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16-le", "cp1252"])
def test_decode_roundtrip(encoding):
    raw = encode_like("line one\r\nSSN 123-45-6789\n", encoding)
    assert encode_like(decode(raw, encoding), encoding) == raw


def test_decode_roundtrip_invalid_utf8_bytes():
    raw = b"ok \xff\xfe bytes"
    assert encode_like(decode(raw, "utf-8"), "utf-8") == raw


# --- entities -------------------------------------------------------------------------------


def test_validate_type_names_hints():
    validate_type_names({"SSN", "EMAIL"})
    with pytest.raises(ValueError, match="CREDIT_DEBIT_NUMBER"):
        validate_type_names({"CREDIT_CARD"})
