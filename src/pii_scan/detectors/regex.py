"""Regex detector with validators. Built-in patterns are written to run in linear time."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ..entities import CUSTOM_RULE_SEVERITY, KNOWN_TYPES
from ..models import Severity, Span

Validator = Callable[[str], bool]


def luhn(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|3[068]|6011|65|64[4-9]|35)")


def card_number(value: str) -> bool:
    digits = "".join(c for c in value if c.isdigit())
    return bool(_CARD_PREFIX.match(digits)) and luhn(digits) and len(set(digits)) > 1


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    type: str
    pattern: re.Pattern[str]
    group: int = 0  # capture group holding the sensitive value (0 = whole match)
    score: float = 1.0
    validator: Validator | None = None
    severity: Severity | None = None  # overrides the type default (custom rules)
    # Cheap prefilter: the regex runs only if one of these literals occurs in the text
    # (compared against lowercased text when `triggers_ci`).
    triggers: tuple[str, ...] = ()
    triggers_ci: bool = False


def _r(id: str, type: str, pattern: str, *, group: int = 0, score: float = 1.0,
       validator: Validator | None = None, triggers: tuple[str, ...] = (), ci: bool = False) -> Rule:  # fmt: skip
    return Rule(id, type, re.compile(pattern), group, score, validator, None, triggers, ci)


BUILTIN_RULES: tuple[Rule, ...] = (
    _r("aws-access-key-id", "AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
       triggers=("AKIA", "ASIA", "ABIA", "ACCA")),
    _r("aws-secret-access-key", "AWS_SECRET_KEY",
       r"(?i)aws[_ ]?secret[_ ]?(?:access[_ ]?)?key[\"']?[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
       group=1, triggers=("secret",), ci=True),
    _r("private-key-block", "PRIVATE_KEY",
       r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----[A-Za-z0-9+/=\s:,-]{0,16384}?"
       r"-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----", triggers=("PRIVATE KEY-----",)),
    _r("private-key-header", "PRIVATE_KEY", r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----",
       triggers=("PRIVATE KEY-----",)),
    _r("github-token", "GITHUB_TOKEN", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
       triggers=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    _r("slack-token", "SLACK_TOKEN", r"\bxox[abposr]-[A-Za-z0-9-]{10,250}\b", triggers=("xox",)),
    _r("stripe-live-key", "STRIPE_KEY", r"\b[rs]k_live_[A-Za-z0-9]{20,247}\b", triggers=("k_live_",)),
    _r("google-api-key", "GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b", triggers=("AIza",)),
    _r("jwt", "JWT", r"\beyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}",
       triggers=("eyJ",)),
    _r("bearer-token", "BEARER_TOKEN", r"(?i)\bbearer[ \t]+([A-Za-z0-9._~+/-]{20,4096}=*)", group=1,
       triggers=("bearer",), ci=True),
    _r("connection-string-password", "CONNECTION_STRING",
       r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqps?|mssql|sqlserver)"
       r"://[^\s:/@]{1,256}:([^\s@/]{1,256})@",
       group=1, triggers=("://",)),
    _r("password-assignment-quoted", "PASSWORD",
       r"(?i)\b(?:password|passwd|pwd)[\"']?[ \t]*[:=][ \t]*([\"'])([^\"'\r\n]{4,200})\1", group=2,
       triggers=("pass", "pwd"), ci=True),
    _r("password-assignment", "PASSWORD",
       r"(?i)\b(?:password|passwd|pwd)[ \t]*[:=][ \t]*(?![\"'])([^\s\"',;]{4,200})", group=1, score=0.9,
       triggers=("pass", "pwd"), ci=True),
    _r("api-key-assignment", "API_KEY",
       r"(?i)\b(?:api[_-]?key|apikey|x-api-key)[\"']?[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9_\-./+=]{12,200})",
       group=1, score=0.9, triggers=("api",), ci=True),
    _r("generic-secret-assignment", "GENERIC_SECRET",
       r"(?i)\b(?:client[_-]?secret|secret[_-]?key|secret|auth[_-]?token|access[_-]?token)[\"']?[ \t]*"
       r"[:=][ \t]*([\"'])([^\"'\r\n]{8,200})\1",
       group=2, score=0.9, triggers=("secret", "token"), ci=True),
    _r("us-ssn", "SSN", r"\b(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}\b"),
    _r("payment-card", "CREDIT_DEBIT_NUMBER", r"\b\d(?:[ -]?\d){12,18}\b", validator=card_number),
    # not preceded by ':' or '/' so "user:password@host" in connection URLs is not an email
    _r("email", "EMAIL", r"(?<![\w.%+:/-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b",
       triggers=("@",)),
)  # fmt: skip


def load_custom_rules(path: Path) -> list[Rule]:
    """Load custom rules.

    Accepts the legacy format `{"Label": "pattern", ...}` or
    `{"rules": [{"id", "pattern", "type"?, "severity"?, "group"?}, ...]}`.
    Raises ValueError on any invalid entry (a bad policy file must stop the run).
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load custom rules from {path}: {exc}") from exc

    entries: Iterable[dict]
    if isinstance(raw, dict) and "rules" in raw:
        entries = raw["rules"]
    elif isinstance(raw, dict):
        entries = [{"id": k, "pattern": v} for k, v in raw.items()]
    else:
        raise ValueError(f"{path}: expected a JSON object")

    rules: list[Rule] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not isinstance(e.get("pattern"), str) or not e.get("id"):
            raise ValueError(f"{path}: rule #{i + 1} needs string 'id' and 'pattern'")
        rule_type = str(e.get("type") or f"CUSTOM:{e['id']}")
        if rule_type not in KNOWN_TYPES and not rule_type.startswith("CUSTOM:"):
            raise ValueError(f"{path}: rule {e['id']!r} has unknown type {rule_type!r}")
        try:
            pattern = _compile_custom(e["pattern"])
        except re.error as exc:
            raise ValueError(f"{path}: rule {e['id']!r} has an invalid pattern: {exc}") from exc
        group = int(e.get("group", 0))
        if group > pattern.groups:
            raise ValueError(f"{path}: rule {e['id']!r} group {group} does not exist")
        severity = Severity.parse(e["severity"]) if e.get("severity") else (
            None if rule_type in KNOWN_TYPES else CUSTOM_RULE_SEVERITY
        )  # fmt: skip
        rules.append(Rule(str(e["id"]), rule_type, pattern, group, 1.0, None, severity))
    return rules


def _compile_custom(pattern: str) -> re.Pattern[str]:
    """Prefer RE2 (linear time) for untrusted custom patterns when google-re2 is installed."""
    try:
        import re2  # type: ignore[import-not-found]
    except ImportError:
        return re.compile(pattern)
    try:
        return re2.compile(pattern)  # type: ignore[no-any-return]
    except Exception:  # noqa: BLE001 - RE2 rejects backreferences/lookarounds; fall back to re
        return re.compile(pattern)


class RegexDetector:
    name = "regex"

    def __init__(self, rules: Iterable[Rule], *, max_matches_per_rule: int = 10_000) -> None:
        self.rules = tuple(rules)
        self.max_matches = max_matches_per_rule

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        lowered: str | None = None
        for rule in self.rules:
            if rule.triggers:
                if rule.triggers_ci:
                    if lowered is None:
                        lowered = text.lower()
                    hay = lowered
                else:
                    hay = text
                if not any(t in hay for t in rule.triggers):
                    continue
            count = 0
            for m in rule.pattern.finditer(text):
                start, end = m.span(rule.group)
                if start < 0 or end <= start:
                    continue
                if rule.validator and not rule.validator(text[start:end]):
                    continue
                out.append(Span(start, end, rule.type, rule.score, self.name, rule.id))
                count += 1
                if count >= self.max_matches:
                    break
        return out

    def severity_overrides(self) -> dict[str, Severity]:
        return {r.type: r.severity for r in self.rules if r.severity is not None}
