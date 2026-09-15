"""Core data types shared by sources, detectors, sinks, and masking."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    """Ordered so that comparisons (`>=`) express "at least this severe"."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    def __str__(self) -> str:
        return self.name.lower()


class Status(StrEnum):
    """Outcome for one file. Only CLEAN and FINDINGS mean the file was fully analyzed."""

    CLEAN = "clean"
    FINDINGS = "findings"
    NOT_SCANNED = "not_scanned"  # could not be fully analyzed (error, binary, too large, ...)
    EXCLUDED = "excluded"  # skipped on purpose by policy (exclude rules)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Span:
    """A detected entity as a half-open character range [start, end) into the decoded text."""

    start: int
    end: int
    type: str
    score: float
    detector: str  # "regex" | "comprehend" | ...
    rule: str = ""  # regex rule id or empty


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    start: int
    end: int
    type: str
    severity: Severity
    score: float
    detector: str
    rule: str
    preview: str  # masked, never the raw value
    fingerprint: str  # keyed HMAC of the raw value (stable within a run key)


@dataclass(slots=True)
class FileResult:
    path: str
    status: Status
    reason: str = ""
    size: int = 0
    encoding: str = ""
    findings: list[Finding] = field(default_factory=list)
    masked_path: str = ""
    relpath: str = ""
    mtime_ns: int = 0
    sha256: str = ""
    suppressed: int = 0  # findings hidden by the baseline
    suppressed_findings: list[Finding] = field(default_factory=list)  # kept for masking and baselines
    cached: bool = False
