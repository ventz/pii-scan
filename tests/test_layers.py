"""AWS layers against botocore's Stubber: no network, no credentials."""

import threading
from pathlib import Path

import pytest
from botocore.stub import ANY, Stubber

from pii_scan.detectors.aws import AwsSession, AwsSettings, ComprehendDetector, ContainsScreen, GuardrailsDetector
from pii_scan.detectors.regex import BUILTIN_RULES, RegexDetector
from pii_scan.masking import Masker
from pii_scan.models import Status
from pii_scan.pipeline import Scanner
from pii_scan.settings import Settings
from pii_scan.sources.fs import Excludes, FilesystemSource

TYPES = frozenset({"NAME", "EMAIL", "SSN"})
USAGE = {
    "topicPolicyUnits": 0, "contentPolicyUnits": 0, "wordPolicyUnits": 0,
    "sensitiveInformationPolicyUnits": 1, "sensitiveInformationPolicyFreeUnits": 0,
    "contextualGroundingPolicyUnits": 0,
}  # fmt: skip


class Collect:
    def __init__(self):
        self.results = []
        self.summary = None

    def file(self, r):
        self.results.append(r)

    def close(self, s):
        self.summary = s


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    session = AwsSession(AwsSettings(region="us-east-1", guardrail_id="gr1", tps_contains=1000, tps_detect=1000,
                                     guardrail_chars_per_second=10**9))
    stubs = {}
    for service in ("comprehend", "bedrock-runtime"):
        client = session.client(service)
        stub = Stubber(client)
        stub.activate()
        stubs[service] = stub
    return session, stubs


def scan(tmp_path: Path, text: str, layers, aws_session):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.txt").write_text(text, encoding="utf-8")
    s = Settings(paths=(str(root),), scan_all=True, layers=("regex", *[type(x).name for x in []]),
                 fail_on=None, workers=1)  # fmt: skip
    sink = Collect()
    scanner = Scanner(s, FilesystemSource([root], Excludes(), max_file_size=10**6), RegexDetector(BUILTIN_RULES),
                      layers, Masker(), sink, aws=aws_session, stop=threading.Event(), api_threads=2)  # fmt: skip
    summary = scanner.run()
    return sink.results, summary


def test_contains_negative_skips_detect(tmp_path, aws):
    session, stubs = aws
    stubs["comprehend"].add_response("contains_pii_entities", {"Labels": []}, {"Text": ANY, "LanguageCode": "en"})
    layers = [ContainsScreen(session, TYPES, 0.5), ComprehendDetector(session, TYPES, 0.5)]
    results, summary = scan(tmp_path, "just some words\n", layers, session)
    assert results[0].status is Status.CLEAN
    assert session.usage.calls == {"contains": 1, "detect": 0, "guardrails": 0}
    stubs["comprehend"].assert_no_pending_responses()


def test_contains_positive_runs_detect_with_offsets(tmp_path, aws):
    session, stubs = aws
    text = "😀 Hello Jane Roe, bye\n"
    stubs["comprehend"].add_response("contains_pii_entities", {"Labels": [{"Name": "NAME", "Score": 0.9}]},
                                     {"Text": ANY, "LanguageCode": "en"})  # fmt: skip
    b = text.index("Jane Roe")
    stubs["comprehend"].add_response(
        "detect_pii_entities",
        {"Entities": [{"Type": "NAME", "Score": 0.99, "BeginOffset": b, "EndOffset": b + 8}]},
        {"Text": ANY, "LanguageCode": "en"},
    )
    layers = [ContainsScreen(session, TYPES, 0.5), ComprehendDetector(session, TYPES, 0.5)]
    results, _ = scan(tmp_path, text, layers, session)
    (f,) = results[0].findings
    assert (f.type, f.line, f.column, f.preview) == ("NAME", 1, 9, "[NAME, 8 chars]")


def test_guardrails_matches_are_located(tmp_path, aws):
    session, stubs = aws
    text = "ask Jane Roe, then ask Jane  Roe again\n"
    hit = {"match": "Jane Roe", "type": "NAME", "action": "ANONYMIZED", "detected": True}
    policy = {"piiEntities": [hit], "regexes": []}
    stubs["bedrock-runtime"].add_response(
        "apply_guardrail",
        {"action": "GUARDRAIL_INTERVENED", "outputs": [], "usage": USAGE,
         "assessments": [{"sensitiveInformationPolicy": policy}]},
        {"guardrailIdentifier": "gr1", "guardrailVersion": "DRAFT", "source": "INPUT", "content": ANY},
    )  # fmt: skip
    results, _ = scan(tmp_path, text, [GuardrailsDetector(session, TYPES)], session)
    guard = [f for f in results[0].findings if f.detector == "guardrails"]
    assert [f.start for f in guard] == [4]  # exact match only; "Jane  Roe" has two spaces
    assert session.usage.calls["guardrails"] == 1


def test_guardrails_whitespace_normalized_match(tmp_path, aws):
    session, stubs = aws
    text = "ask Jane\n  Roe please\n"
    hit = {"match": "Jane Roe", "type": "NAME", "action": "ANONYMIZED", "detected": True}
    stubs["bedrock-runtime"].add_response(
        "apply_guardrail",
        {"action": "GUARDRAIL_INTERVENED", "outputs": [], "usage": USAGE,
         "assessments": [{"sensitiveInformationPolicy": {"piiEntities": [hit], "regexes": []}}]},
        {"guardrailIdentifier": "gr1", "guardrailVersion": "DRAFT", "source": "INPUT", "content": ANY},
    )  # fmt: skip
    results, _ = scan(tmp_path, text, [GuardrailsDetector(session, TYPES)], session)
    (f,) = results[0].findings
    assert (f.start, f.end) == (4, 14)


def test_guardrail_without_active_pii_filter_aborts(tmp_path, aws):
    """Regression: a guardrail with input PII detection disabled returns NONE with zero policy units."""
    session, stubs = aws
    zero = {**USAGE, "sensitiveInformationPolicyUnits": 0}
    stubs["bedrock-runtime"].add_response(
        "apply_guardrail",
        {"action": "NONE", "outputs": [], "usage": zero, "assessments": [{"invocationMetrics": {
            "guardrailProcessingLatency": 30, "usage": zero,
            "guardrailCoverage": {"textCharacters": {"guarded": 20, "total": 20}}}}]},
        {"guardrailIdentifier": "gr1", "guardrailVersion": "DRAFT", "source": "INPUT", "content": ANY},
    )  # fmt: skip
    results, summary = scan(tmp_path, "Jane Roe lives here\n", [GuardrailsDetector(session, TYPES)], session)
    assert results[0].status is Status.NOT_SCANNED
    assert "sensitive information filter" in summary.aborted
    assert summary.exit_code(False) == 2


def test_throttled_file_is_not_scanned_never_clean(tmp_path, aws):
    session, stubs = aws
    stubs["comprehend"].add_client_error("detect_pii_entities", "ThrottlingException", "Rate exceeded")
    results, summary = scan(tmp_path, "Jane Roe\n", [ComprehendDetector(session, TYPES, 0.5)], session)
    assert results[0].status is Status.NOT_SCANNED
    assert summary.exit_code(allow_incomplete=False) == 3


def test_access_denied_aborts_run(tmp_path, aws):
    session, stubs = aws
    stubs["comprehend"].add_client_error("detect_pii_entities", "AccessDeniedException", "no")
    results, summary = scan(tmp_path, "Jane Roe\n", [ComprehendDetector(session, TYPES, 0.5)], session)
    assert summary.aborted and summary.exit_code(False) == 2
    assert results[0].status is Status.NOT_SCANNED
