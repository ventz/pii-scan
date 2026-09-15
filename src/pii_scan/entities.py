"""Entity type catalog: AWS Comprehend PII types plus regex-only secret types, with default severities."""

from __future__ import annotations

from .models import Severity

# Every PiiEntityType accepted by AWS Comprehend DetectPiiEntities (API_PiiEntity, 2026).
COMPREHEND_TYPES: frozenset[str] = frozenset(
    {
        "BANK_ACCOUNT_NUMBER", "BANK_ROUTING", "CREDIT_DEBIT_NUMBER", "CREDIT_DEBIT_CVV",
        "CREDIT_DEBIT_EXPIRY", "PIN", "EMAIL", "ADDRESS", "NAME", "PHONE", "SSN", "DATE_TIME",
        "PASSPORT_NUMBER", "DRIVER_ID", "URL", "AGE", "USERNAME", "PASSWORD", "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY", "IP_ADDRESS", "MAC_ADDRESS", "LICENSE_PLATE",
        "VEHICLE_IDENTIFICATION_NUMBER", "INTERNATIONAL_BANK_ACCOUNT_NUMBER", "SWIFT_CODE",
        "UK_NATIONAL_INSURANCE_NUMBER", "UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER",
        "UK_NATIONAL_HEALTH_SERVICE_NUMBER", "CA_SOCIAL_INSURANCE_NUMBER", "CA_HEALTH_NUMBER",
        "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER", "IN_PERMANENT_ACCOUNT_NUMBER", "IN_NREGA",
        "IN_AADHAAR", "IN_VOTER_NUMBER",
    }
)  # fmt: skip

# Types produced only by built-in regex rules (secrets are not PII, but belong in the same report).
REGEX_ONLY_TYPES: frozenset[str] = frozenset(
    {
        "PRIVATE_KEY", "GITHUB_TOKEN", "SLACK_TOKEN", "JWT", "BEARER_TOKEN", "API_KEY",
        "GENERIC_SECRET", "CONNECTION_STRING", "STRIPE_KEY", "GOOGLE_API_KEY",
    }
)  # fmt: skip

KNOWN_TYPES: frozenset[str] = COMPREHEND_TYPES | REGEX_ONLY_TYPES

_CRITICAL = {
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD", "SSN", "CREDIT_DEBIT_NUMBER",
    "BANK_ACCOUNT_NUMBER", "PRIVATE_KEY", "GITHUB_TOKEN", "SLACK_TOKEN", "STRIPE_KEY",
    "CONNECTION_STRING", "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER",
    "INTERNATIONAL_BANK_ACCOUNT_NUMBER",
}  # fmt: skip
_HIGH = {
    "CREDIT_DEBIT_CVV", "CREDIT_DEBIT_EXPIRY", "PIN", "BANK_ROUTING", "PASSPORT_NUMBER",
    "DRIVER_ID", "UK_NATIONAL_INSURANCE_NUMBER", "UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER",
    "UK_NATIONAL_HEALTH_SERVICE_NUMBER", "CA_SOCIAL_INSURANCE_NUMBER", "CA_HEALTH_NUMBER",
    "IN_PERMANENT_ACCOUNT_NUMBER", "IN_NREGA", "IN_AADHAAR", "IN_VOTER_NUMBER", "JWT",
    "BEARER_TOKEN", "API_KEY", "GENERIC_SECRET", "GOOGLE_API_KEY",
}  # fmt: skip
_MEDIUM = {"NAME", "ADDRESS", "PHONE", "EMAIL", "USERNAME", "SWIFT_CODE"}

DEFAULT_SEVERITY: dict[str, Severity] = {
    t: (
        Severity.CRITICAL if t in _CRITICAL
        else Severity.HIGH if t in _HIGH
        else Severity.MEDIUM if t in _MEDIUM
        else Severity.LOW
    )
    for t in KNOWN_TYPES
}  # fmt: skip

# Default for custom regex rules that do not declare a severity.
CUSTOM_RULE_SEVERITY = Severity.HIGH


def validate_type_names(names: set[str] | frozenset[str], *, allow_custom: bool = False) -> None:
    """Raise ValueError listing any unknown entity type names (catches typos like CREDIT_CARD)."""
    unknown = sorted(
        n for n in names if n not in KNOWN_TYPES and not (allow_custom and n.startswith("CUSTOM:"))
    )
    if unknown:
        hints = {
            "CREDIT_CARD": "CREDIT_DEBIT_NUMBER",
            "PHONE_NUMBER": "PHONE",
            "TAX_ID": "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER",
        }
        detail = ", ".join(f"{u} (did you mean {hints[u]}?)" if u in hints else u for u in unknown)
        raise ValueError(f"unknown entity type(s): {detail}")
