"""Regex detector with validators. Built-in patterns are written to run in linear time."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ..entities import CUSTOM_RULE_SEVERITY, KNOWN_TYPES
from ..models import Severity, Span
from .base import DetectorError

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


_SURROGATES = re.compile("[\ud800-\udfff]")
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
       # the body may not contain another BEGIN, so repeated headers can't make each attempt scan 16 KB
       r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S]){0,16384}?"
       r"-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----", triggers=("PRIVATE KEY-----",)),
    _r("private-key-header", "PRIVATE_KEY", r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY-----",
       triggers=("PRIVATE KEY-----",)),
    _r("github-token", "GITHUB_TOKEN", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
       triggers=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    _r("slack-token", "SLACK_TOKEN", r"\bxox[abposr]-[A-Za-z0-9-]{10,250}\b", triggers=("xox",)),
    _r("stripe-live-key", "STRIPE_KEY", r"\b[rs]k_live_[A-Za-z0-9]{20,247}\b", triggers=("k_live_",)),
    _r("google-api-key", "GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b", triggers=("AIza",)),
    # lookbehind allows one start per run of token characters (no quadratic retries on "eyJeyJ...")
    _r("jwt", "JWT", r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}",
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


def load_custom_rules(path: Path, *, require_re2: bool = False) -> list[Rule]:
    """Load custom rules.

    Accepts the legacy format `{"Label": "pattern", ...}` or
    `{"rules": [{"id", "pattern", "type"?, "severity"?, "group"?}, ...]}`.
    Raises ValueError on any invalid entry (a bad policy file must stop the run).
    With `require_re2` (untrusted rules, --restricted-config) every pattern must compile with RE2,
    so a rule from a pull request can't hang the scan with catastrophic backtracking.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load custom rules from {path}: {exc}") from exc

    if isinstance(raw, dict) and "rules" in raw:
        entries = raw["rules"]
        if not isinstance(entries, list):
            raise ValueError(f"{path}: 'rules' must be a list")
    elif isinstance(raw, dict):
        entries = [{"id": k, "pattern": v} for k, v in raw.items()]
    else:
        raise ValueError(f"{path}: expected a JSON object")

    if require_re2 and len(entries) > MAX_UNTRUSTED_RULES:
        raise ValueError(f"{path}: more than {MAX_UNTRUSTED_RULES} rules, which --restricted-config refuses")
    rules: list[Rule] = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not isinstance(e.get("pattern"), str) or not isinstance(e.get("id"), str) \
                or not e["id"]:
            raise ValueError(f"{path}: rule #{i + 1} needs string 'id' and 'pattern'")
        rule_id = e["id"]
        if require_re2 and len(e["pattern"]) > MAX_UNTRUSTED_PATTERN_CHARS:
            raise ValueError(f"{path}: rule {rule_id!r} pattern is longer than {MAX_UNTRUSTED_PATTERN_CHARS} "
                             "characters, which --restricted-config refuses")  # fmt: skip
        unknown = set(e) - _RULE_KEYS
        if unknown:
            raise ValueError(f"{path}: rule {rule_id!r} has unknown key(s): {', '.join(sorted(unknown))}")
        rule_type = e.get("type", f"CUSTOM:{rule_id}")
        if not isinstance(rule_type, str) or (rule_type not in KNOWN_TYPES and not rule_type.startswith("CUSTOM:")):
            raise ValueError(f"{path}: rule {rule_id!r} has unknown type {rule_type!r}")
        try:
            pattern = _compile_custom(e["pattern"], require_re2=require_re2)
        except _RE2Required as exc:
            raise ValueError(f"{path}: rule {rule_id!r}: {exc}") from exc
        except re.error as exc:
            raise ValueError(f"{path}: rule {rule_id!r} has an invalid pattern: {exc}") from exc
        group = e.get("group", 0)
        if not isinstance(group, int) or isinstance(group, bool) or not 0 <= group <= pattern.groups:
            raise ValueError(f"{path}: rule {rule_id!r} group {group!r} does not exist")
        severity = e.get("severity")
        if severity is None:
            severity = None if rule_type in KNOWN_TYPES else CUSTOM_RULE_SEVERITY
        elif isinstance(severity, str):
            severity = Severity.parse(severity)
        else:
            raise ValueError(f"{path}: rule {rule_id!r} severity must be a string")
        rules.append(Rule(rule_id, rule_type, pattern, group, 1.0, None, severity))
    return rules


_RULE_KEYS = frozenset({"id", "pattern", "type", "severity", "group"})
# Limits for rules from an untrusted tree (--restricted-config): RE2 is linear, but not free.
MAX_UNTRUSTED_RULES = 200
MAX_UNTRUSTED_PATTERN_CHARS = 1000


class _RE2Required(Exception):
    pass


def _compile_custom(pattern: str, *, require_re2: bool = False) -> re.Pattern[str]:
    """Prefer RE2 (linear time) for custom patterns when google-re2 is installed.

    Trusted rules fall back to Python `re` for syntax RE2 lacks; with `require_re2` they never do.
    """
    try:
        import re2  # type: ignore[import-not-found]
    except ImportError:
        if require_re2:
            raise _RE2Required("custom rules under --restricted-config need google-re2 "
                               "(install pii-scan[re2])") from None  # fmt: skip
        return re.compile(pattern)
    if not hasattr(re2, "Options"):  # some other package named "re2", possibly backed by Python re
        if require_re2:
            raise _RE2Required("the installed 're2' module is not google-re2 (install pii-scan[re2])")
        return re.compile(pattern)
    options = re2.Options()
    options.log_errors = False  # rejections are reported as errors here, not as C++ log lines on stderr
    try:
        return re2.compile(pattern, options)  # type: ignore[no-any-return]
    except Exception as exc:  # noqa: BLE001 - RE2 rejects backreferences/lookarounds
        if require_re2:
            raise _RE2Required(f"pattern is not valid RE2 syntax, which --restricted-config requires "
                               f"(no lookarounds or backreferences): {exc}") from None  # fmt: skip
        return re.compile(pattern)


class RegexDetector:
    name = "regex"

    def __init__(self, rules: Iterable[Rule], *, max_matches_per_rule: int = 10_000) -> None:
        self.rules = tuple(rules)
        self.max_matches = max_matches_per_rule

    def detect(self, text: str) -> list[Span]:
        out: list[Span] = []
        lowered: str | None = None
        re2_text: str | None = None
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
            hay_text = text
            if not isinstance(rule.pattern, re.Pattern):
                # google-re2 encodes to strict UTF-8, which lone surrogates (undecodable bytes) fail.
                # One U+FFFD per surrogate keeps every offset unchanged.
                if re2_text is None:
                    re2_text = text if text.isascii() else _SURROGATES.sub("\ufffd", text)
                hay_text = re2_text
            count = 0
            for m in rule.pattern.finditer(hay_text):
                start, end = m.span(rule.group)
                if start < 0 or end <= start:
                    continue
                if rule.validator and not rule.validator(text[start:end]):
                    continue
                count += 1
                if count > self.max_matches:
                    # Never return a truncated result: unreported matches would also stay unmasked.
                    raise DetectorError(f"match_limit: rule {rule.id} matched more than {self.max_matches} times")
                out.append(Span(start, end, rule.type, rule.score, self.name, rule.id))
        return out
