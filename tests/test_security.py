"""Regression tests for the pre-release security audit."""

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

from pii_scan.cli import main
from pii_scan.detectors.regex import BUILTIN_RULES, RegexDetector
from pii_scan.masking import Masker, MaskStyle, safe_output_path
from pii_scan.sniff import decode, detect_encoding, encode_like
from pii_scan.sources.base import ReadError
from pii_scan.sources.fs import read_regular_file

from .conftest import git, requires_symlinks

KEY = "0123456789abcdef-test-key"


def run(*args: str) -> int:
    return main([*args, "--progress", "none", "-q"])


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --- untrusted configuration -------------------------------------------------------------------


@pytest.mark.parametrize("config", [
    {"severity": {"low": ["SSN"]}},
    {"exclude": {"replace_defaults": True, "globs": ["*"]}},
    {"validation_patterns": {"SSN": "(?!)"}},
    {"aws": {"endpoint_url": "https://attacker.example"}},
    {"limits": {"max_matches_per_rule": 1}},
    {"fail_on": "never"},
])  # fmt: skip
def test_restricted_config_rejects_loosening(tree: Path, tmp_path: Path, config):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps(config))
    assert run("--all", str(tree), "--config", str(cfg), "--restricted-config") == 2


def test_restricted_config_allows_raising(tree: Path, tmp_path: Path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"severity": {"critical": ["EMAIL"]}}))
    assert run("--all", str(tree), "--config", str(cfg), "--restricted-config", "--fail-on", "critical") == 1


@pytest.mark.skipif(importlib.util.find_spec("re2") is None, reason="restricted custom rules need google-re2")
def test_restricted_custom_rule_cannot_downgrade(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # untrusted rules files must be under the working directory
    rules = tmp_path / "r.json"
    rules.write_text(json.dumps({"rules": [{"id": "x", "type": "SSN", "severity": "low", "pattern": "QQQ-NEVER"}]}))
    assert run("--all", str(tree), "--custom-regex", str(rules), "--restricted-config") == 2
    assert run("--all", str(tree), "--custom-regex", str(rules), "--fail-on", "never") == 0  # trusted: allowed


# --- git ---------------------------------------------------------------------------------------


def test_git_mode_refuses_repo_with_clean_filter(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("hi\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    marker = tmp_path / "pwned"
    git(repo, "config", "filter.x.clean", f"touch '{marker.as_posix()}'")
    (repo / ".gitattributes").write_text("* filter=x\n")
    assert run(str(repo), "--base", "main") == 2
    assert not marker.exists()


def test_git_mode_allows_standard_lfs_config(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("hi\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "config", "filter.lfs.required", "true")
    assert run(str(repo), "--base", "main") == 0


# --- filesystem --------------------------------------------------------------------------------


@requires_symlinks
def test_read_refuses_file_outside_root(tmp_path: Path):
    inside, outside = tmp_path / "share", tmp_path / "secret"
    inside.mkdir()
    outside.mkdir()
    (outside / "creds.txt").write_text("aws_secret_access_key = x\n")
    (inside / "swapped").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ReadError) as exc:
        read_regular_file(str(inside / "swapped" / "creds.txt"), 1000, root=os.path.realpath(inside))
    assert exc.value.reason == "outside_root"


@requires_symlinks
def test_report_symlink_is_refused(tree: Path, tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    link = tmp_path / "report.jsonl"
    link.symlink_to(victim)
    assert run("--all", str(tree), "--output", "jsonl", "--report", str(link)) == 2
    assert victim.read_text() == "keep me\n"


@requires_symlinks
def test_output_path_symlinked_parent_is_refused(tmp_path: Path):
    out, elsewhere = tmp_path / "out", tmp_path / "elsewhere"
    out.mkdir()
    elsewhere.mkdir()
    (out / "hr").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ValueError):
        safe_output_path(out, "hr/people.txt")


# --- masking from a tampered report ------------------------------------------------------------


def test_mask_from_rechecks_regex_when_findings_are_deleted(tree: Path, tmp_path: Path):
    report, out = tmp_path / "r.jsonl", tmp_path / "masked"
    run("--all", str(tree), "--output", "jsonl", "--report", str(report), "--fail-on", "never")
    kept = [line for line in report.read_text(encoding="utf-8").splitlines() if '"kind":"finding"' not in line]
    report.write_text("\n".join(kept) + "\n", encoding="utf-8")
    assert main(["mask", "--from", str(report), "--out", str(out), "-q"]) == 0
    masked = (out / "hr" / "people.txt").read_text()
    assert "123-45-6789" not in masked and "AKIAIOSFODNN7EXAMPLE" not in masked


# --- regex performance -------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [
    "-eyJ" * 250_000,
    "-----BEGIN PRIVATE KEY-----\n" * 40_000,
    "eyJ" + "a" * 1_000_000,
], ids=["jwt-dashes", "pem-headers", "jwt-run"])  # fmt: skip
def test_builtin_regex_is_fast_on_adversarial_input(payload):
    started = time.perf_counter()
    RegexDetector(BUILTIN_RULES, max_matches_per_rule=10**9).detect(payload)
    assert time.perf_counter() - started < 5


def test_private_key_block_still_matches():
    text = "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"
    spans = [s for s in RegexDetector(BUILTIN_RULES).detect(text) if s.rule == "private-key-block"]
    assert spans and text[spans[0].start:spans[0].end].endswith("END RSA PRIVATE KEY-----")


# --- encodings, keys, budgets ------------------------------------------------------------------


def test_bomless_utf16_is_text_and_round_trips():
    raw = "Name: John Doe\r\nSSN 219-09-9999\r\n".encode("utf-16-le")
    enc = detect_encoding(raw)
    assert enc == "utf-16le"
    assert encode_like(decode(raw, enc), enc) == raw  # no BOM added


def test_short_hmac_key_rejected(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "short")
    assert run("--all", str(tree), "--write-baseline", str(tmp_path / "b.json")) == 2


def test_hash_mask_tag_is_12_hex():
    tag = Masker(MaskStyle.HASH, key=KEY.encode()).replacement("123-45-6789", "SSN")
    assert len(tag.split(":")[1].rstrip("]")) == 12


@pytest.mark.parametrize("var", ["GITHUB_ACTIONS", "JENKINS_URL"])
def test_show_values_refused_in_other_ci_systems(tree: Path, monkeypatch, var):
    monkeypatch.setenv(var, "true")
    assert run("--all", str(tree), "--show-values") == 2


def test_aws_budget_aborts_run(tmp_path: Path, monkeypatch):
    import threading

    from botocore.stub import ANY, Stubber

    from pii_scan.detectors.aws import AwsSession, AwsSettings, ComprehendDetector
    from pii_scan.detectors.base import DetectorError

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    session = AwsSession(AwsSettings(region="us-east-1", max_chars=10, tps_detect=1000), threading.Event())
    stub = Stubber(session.client("comprehend"))
    stub.activate()
    stub.add_response("detect_pii_entities", {"Entities": []}, {"Text": ANY, "LanguageCode": "en"})
    det = ComprehendDetector(session, frozenset({"NAME"}), 0.5)
    det.detect("short")  # 5 chars, within budget
    with pytest.raises(DetectorError) as exc:
        det.detect("this is over budget")
    assert exc.value.fatal
