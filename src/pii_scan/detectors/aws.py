"""AWS layers: Comprehend ContainsPiiEntities (screen), Bedrock Guardrails and Comprehend
DetectPiiEntities (detect). All share one boto3 session, explicit retries, and token buckets.

Every call either returns a result or raises DetectorError. Nothing here returns [] on failure.
"""

from __future__ import annotations

import math
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..models import Span
from ..ratelimit import TokenBucket
from .base import DetectorError

# Errors that will recur on every request: stop the run instead of marking files one by one.
_FATAL_CODES = {
    "AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException",
    "ExpiredTokenException", "ExpiredToken", "InvalidClientTokenId", "AuthFailure",
    "ResourceNotFoundException", "SubscriptionRequiredException", "OptInRequired",
}  # fmt: skip

# Bedrock Guardrails PII type names -> Comprehend names used everywhere else in pii-scan.
GUARDRAIL_TYPE_MAP = {
    "CREDIT_DEBIT_CARD_CVV": "CREDIT_DEBIT_CVV",
    "CREDIT_DEBIT_CARD_EXPIRY": "CREDIT_DEBIT_EXPIRY",
    "CREDIT_DEBIT_CARD_NUMBER": "CREDIT_DEBIT_NUMBER",
    "US_BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT_NUMBER",
    "US_BANK_ROUTING_NUMBER": "BANK_ROUTING",
    "US_PASSPORT_NUMBER": "PASSPORT_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER": "SSN",
}

# List prices (USD) used only for the cost estimate in the run summary. Verify against
# aws.amazon.com/comprehend/pricing and aws.amazon.com/bedrock/pricing for your region.
PRICE_PER_UNIT = {"contains": 0.000002, "detect": 0.0001, "guardrails": 0.0001}


@dataclass(frozen=True, slots=True)
class AwsSettings:
    region: str | None = None
    profile: str | None = None
    endpoint_url: str | None = None  # e.g. a VPC interface endpoint
    language: str = "en"
    tps_contains: float = 20.0  # default quota 25 TPS in every region
    tps_detect: float = 40.0  # default quota 200 (us-east-1) / 100 (us-west-2) / 50 (others)
    guardrail_chars_per_second: float = 20_000.0  # default quota ~25 text units (25,000 chars)/s
    guardrail_id: str | None = None
    guardrail_version: str = "DRAFT"
    max_attempts: int = 8
    pool_size: int = 32
    max_chars: int | None = None  # cost ceiling: characters sent to AWS per run


@dataclass
class Usage:
    """Billable units consumed, for the run summary."""

    units: dict[str, int] = field(default_factory=lambda: {"contains": 0, "detect": 0, "guardrails": 0})
    calls: dict[str, int] = field(default_factory=lambda: {"contains": 0, "detect": 0, "guardrails": 0})
    chars: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, api: str, units: int) -> None:
        with self._lock:
            self.units[api] += units
            self.calls[api] += 1

    def estimated_cost(self) -> float:
        return sum(self.units[k] * PRICE_PER_UNIT[k] for k in self.units)


def comprehend_units(text: str) -> int:
    return max(3, math.ceil(len(text) / 100))


def guardrail_units(text: str) -> int:
    return max(1, math.ceil(len(text) / 1000))


class AwsSession:
    """Lazily creates thread-safe clients with explicit endpoint handling and retries."""

    def __init__(self, settings: AwsSettings, stop: threading.Event | None = None) -> None:
        import boto3
        from botocore.config import Config

        self.settings = settings
        self.stop = stop
        self.usage = Usage()
        self._session = boto3.Session(profile_name=settings.profile, region_name=settings.region)
        if not self._session.region_name:
            raise DetectorError(
                "AWS region is not set. Fix: pass --region, or set AWS_REGION / AWS_DEFAULT_REGION.",
                fatal=True,
            )
        self._config = Config(
            retries={"mode": "adaptive", "max_attempts": settings.max_attempts},
            max_pool_connections=settings.pool_size,
            connect_timeout=10,
            read_timeout=60,
            # Always ignore AWS_ENDPOINT_URL* and endpoint_url from the environment and shared config,
            # so a planted .env or shell variable cannot redirect scanned content for any service.
            # An explicit aws.endpoint_url is still passed to the Comprehend client below.
            ignore_configured_endpoint_urls=True,
        )
        self._clients: dict[str, object] = {}
        self._lock = threading.Lock()
        self.buckets = {
            "contains": TokenBucket(settings.tps_contains),
            "detect": TokenBucket(settings.tps_detect),
            "guardrails": TokenBucket(settings.guardrail_chars_per_second / 1000.0),
        }

    @property
    def region(self) -> str:
        return str(self._session.region_name)

    def client(self, service: str):  # noqa: ANN201 - boto3 client types are dynamic
        with self._lock:
            if service not in self._clients:
                kwargs = {"config": self._config}
                if self.settings.endpoint_url and service == "comprehend":
                    kwargs["endpoint_url"] = self.settings.endpoint_url
                self._clients[service] = self._session.client(service, **kwargs)
            return self._clients[service]

    def identity(self) -> dict[str, str]:
        try:
            ident = self.client("sts").get_caller_identity()
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc, "sts:GetCallerIdentity") from exc
        return {"account": ident.get("Account", ""), "arn": ident.get("Arn", ""), "region": self.region}

    def _acquire(self, api: str, tokens: float, chars: int) -> None:
        limit = self.settings.max_chars
        if limit is not None:
            with self.usage._lock:
                over = self.usage.chars + chars > limit
                if not over:
                    self.usage.chars += chars
            if over:
                raise DetectorError(
                    f"AWS character budget of {limit:,} reached; stopping (raise --aws-max-chars to continue)",
                    fatal=True,
                )
        else:
            with self.usage._lock:
                self.usage.chars += chars
        if not self.buckets[api].acquire(tokens, self.stop):
            raise DetectorError("interrupted")


def _wrap(exc: Exception, op: str) -> DetectorError:
    from botocore.exceptions import (
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        PartialCredentialsError,
    )

    if isinstance(exc, DetectorError):
        return exc
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        return DetectorError(f"{op}: AWS credentials not found. Fix: set AWS_PROFILE or run "
                             "'aws configure' / 'aws sso login'.", fatal=True)  # fmt: skip
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        msg = exc.response.get("Error", {}).get("Message", "")
        return DetectorError(f"{op}: {code}: {msg}", fatal=code in _FATAL_CODES)
    if isinstance(exc, EndpointConnectionError):
        return DetectorError(f"{op}: cannot reach AWS endpoint: {exc}")
    return DetectorError(f"{op}: {type(exc).__name__}: {exc}")


class ContainsScreen:
    """Layer: ContainsPiiEntities. Cheap yes/no with entity labels; no offsets."""

    name = "contains"
    max_bytes = 90_000

    def __init__(self, aws: AwsSession, entity_types: frozenset[str], threshold: float) -> None:
        self.aws = aws
        self.entity_types = entity_types
        self.threshold = threshold

    def screen(self, text: str) -> set[str]:
        """Return the relevant entity types present at or above the threshold."""
        units = comprehend_units(text)
        self.aws._acquire("contains", 1, len(text))
        try:
            resp = self.aws.client("comprehend").contains_pii_entities(
                Text=text, LanguageCode=self.aws.settings.language
            )
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc, "comprehend:ContainsPiiEntities") from exc
        self.aws.usage.add("contains", units)
        return {
            lab["Name"]
            for lab in resp.get("Labels", [])
            if lab.get("Score", 0.0) >= self.threshold and lab.get("Name") in self.entity_types
        }


class ComprehendDetector:
    """Layer: DetectPiiEntities. Exact character offsets and confidence scores."""

    name = "comprehend"
    max_bytes = 90_000

    def __init__(self, aws: AwsSession, entity_types: frozenset[str], min_confidence: float) -> None:
        self.aws = aws
        self.entity_types = entity_types
        self.min_confidence = min_confidence

    def detect(self, text: str) -> list[Span]:
        units = comprehend_units(text)
        self.aws._acquire("detect", 1, len(text))
        try:
            resp = self.aws.client("comprehend").detect_pii_entities(
                Text=text, LanguageCode=self.aws.settings.language
            )
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc, "comprehend:DetectPiiEntities") from exc
        self.aws.usage.add("detect", units)
        n = len(text)
        spans: list[Span] = []
        for e in resp.get("Entities", []):
            t, score = e.get("Type", ""), float(e.get("Score", 0.0))
            b, end = int(e.get("BeginOffset", -1)), int(e.get("EndOffset", -1))
            if t not in self.entity_types or score < self.min_confidence:
                continue
            if not 0 <= b < end <= n:
                raise DetectorError(f"comprehend:DetectPiiEntities returned out-of-range offsets {b}-{end}")
            spans.append(Span(b, end, t, score, self.name))
        return spans


def _sensitive_policy_evaluated(resp: dict) -> bool:
    """True if the sensitive information filter processed any text units in this call."""
    usages = [resp.get("usage") or {}]
    usages += [(a.get("invocationMetrics") or {}).get("usage") or {} for a in resp.get("assessments", [])]
    return any(
        (u.get("sensitiveInformationPolicyUnits") or 0) + (u.get("sensitiveInformationPolicyFreeUnits") or 0) > 0
        for u in usages
    )


class GuardrailsDetector:
    """Layer: Bedrock ApplyGuardrail sensitive-information filter.

    Guardrails report each match's text and type but no offsets or scores, so offsets are
    recovered by locating the match text in the chunk (every occurrence is masked). A match that
    cannot be located makes the chunk fail rather than silently dropping it.
    """

    name = "guardrails"
    max_bytes = 20_000
    score = 0.9

    def __init__(self, aws: AwsSession, entity_types: frozenset[str]) -> None:
        if not aws.settings.guardrail_id:
            raise DetectorError("the guardrails layer needs --guardrail-id (see docs/detection-layers.md)",
                                fatal=True)  # fmt: skip
        self.aws = aws
        self.entity_types = entity_types

    def detect(self, text: str) -> list[Span]:
        units = guardrail_units(text)
        self.aws._acquire("guardrails", units, len(text))
        s = self.aws.settings
        try:
            resp = self.aws.client("bedrock-runtime").apply_guardrail(
                guardrailIdentifier=s.guardrail_id,
                guardrailVersion=s.guardrail_version,
                source="INPUT",
                content=[{"text": {"text": text}}],
            )
        except Exception as exc:  # noqa: BLE001
            raise _wrap(exc, "bedrock:ApplyGuardrail") from exc
        self.aws.usage.add("guardrails", units)
        if text.strip() and not _sensitive_policy_evaluated(resp):
            # A guardrail whose sensitive information filter is missing or disabled for inputs returns
            # "no action" for everything. Treat that as a configuration error, never as clean text.
            raise DetectorError(
                "bedrock:ApplyGuardrail: the guardrail did not evaluate a sensitive information filter on "
                "input text (sensitiveInformationPolicyUnits=0). Enable PII entities for inputs "
                "(inputEnabled=true) on the guardrail. See docs/detection-layers.md.",
                fatal=True,
            )
        spans: list[Span] = []
        for assessment in resp.get("assessments", []):
            policy = assessment.get("sensitiveInformationPolicy") or {}
            for hit in policy.get("piiEntities", []):
                if hit.get("detected") is False:
                    continue
                t = GUARDRAIL_TYPE_MAP.get(hit.get("type", ""), hit.get("type", ""))
                if t not in self.entity_types:
                    continue
                spans.extend(self._locate(text, hit.get("match", ""), t, "guardrails-pii"))
            for hit in policy.get("regexes", []):
                if hit.get("detected") is False:
                    continue
                name = hit.get("name", "regex")
                spans.extend(self._locate(text, hit.get("match", ""), f"CUSTOM:{name}", "guardrails-regex"))
        return spans

    def _locate(self, text: str, match: str, entity_type: str, rule: str) -> Iterable[Span]:
        if not match:
            return []
        found = [(m.start(), m.end()) for m in re.finditer(re.escape(match), text)]
        if not found:
            # tolerate whitespace normalization by the service
            parts = [re.escape(p) for p in match.split()]
            if parts:
                found = [(m.start(), m.end()) for m in re.finditer(r"\s+".join(parts), text)]
        if not found:
            raise DetectorError(
                f"bedrock:ApplyGuardrail reported a {entity_type} match that is not present in the text"
            )
        return [Span(b, e, entity_type, self.score, self.name, rule) for b, e in found]
