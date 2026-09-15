import json
import os
from pathlib import Path

import pytest

from pii_scan.cli import main
from pii_scan.detectors.regex import BUILTIN_RULES, RegexDetector
from pii_scan.sources.base import ReadError
from pii_scan.sources.fs import read_regular_file

from .conftest import SAMPLE, git


def run(*args: str) -> int:
    return main([*args, "--progress", "none"])


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --- regex -------------------------------------------------------------------------------------


def test_regex_rules_on_sample():
    spans = RegexDetector(BUILTIN_RULES).detect(SAMPLE)
    found = {(s.type, SAMPLE[s.start:s.end]) for s in spans}
    assert ("SSN", "123-45-6789") in found
    assert ("CREDIT_DEBIT_NUMBER", "4111 1111 1111 1111") in found
    assert ("PASSWORD", "P@ssw0rd123!") in found
    assert ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE") in found
    assert ("AWS_SECRET_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") in found
    assert ("CONNECTION_STRING", "hunter2secret") in found
    assert ("EMAIL", "john.doe@example.com") in found
    assert not any(t == "CREDIT_DEBIT_NUMBER" and v.startswith("1234") for t, v in found)  # fails Luhn


def test_ssn_rule_rejects_invalid_areas():
    det = RegexDetector(BUILTIN_RULES)
    for bad in ("000-12-3456", "666-12-3456", "912-12-3456", "123-00-4567", "123-45-0000"):
        assert not [s for s in det.detect(f"x {bad} y") if s.type == "SSN"], bad


# --- filesystem safety -------------------------------------------------------------------------


def test_read_refuses_symlink_and_fifo(tree: Path):
    with pytest.raises(ReadError) as exc:
        read_regular_file(str(tree / "link.txt"), 1000)
    assert exc.value.reason == "symlink"
    if (tree / "pipe").exists():
        with pytest.raises(ReadError) as exc:
            read_regular_file(str(tree / "pipe"), 1000)
        assert exc.value.reason == "not_regular_file"


def test_read_enforces_size_limit(tmp_path: Path):
    p = tmp_path / "big.txt"
    p.write_bytes(b"a" * 101)
    with pytest.raises(ReadError) as exc:
        read_regular_file(str(p), 100)
    assert exc.value.reason == "too_large"


# --- end-to-end scan ---------------------------------------------------------------------------


def test_full_scan_jsonl(tree: Path, tmp_path: Path):
    report = tmp_path / "r.jsonl"
    code = run("--all", str(tree), "--output", "jsonl", "--report", str(report), "-q")
    assert code == 1  # critical findings, default --fail-on high
    recs = records(report)
    files = {r["relpath"]: r for r in recs if r["kind"] == "file"}
    assert set(files) == {"hr/people.txt", "hr/crlf.txt", "hr/legacy.txt", "hr/wide.txt", "clean.txt"}
    assert files["hr/legacy.txt"]["encoding"] == "cp1252"
    assert files["hr/wide.txt"]["encoding"] == "utf-16-le"
    assert files["clean.txt"]["status"] == "clean"
    summary = recs[-1]
    assert summary["kind"] == "summary"
    assert summary["excluded_reasons"].get("symlink") == 1
    assert summary["excluded_reasons"].get("binary") == 1
    raw = report.read_text()
    for secret in ("AKIAIOSFODNN7EXAMPLE", "123-45-6789", "P@ssw0rd123!", "hunter2secret"):
        assert secret not in raw  # values never reach reports by default
    ssn = [r for r in recs if r["kind"] == "finding" and r["relpath"] == "hr/crlf.txt"]
    assert ssn and (ssn[0]["line"], ssn[0]["column"]) == (2, 5)


def test_fail_on_never_and_text_output(tree: Path, capsys):
    assert run("--all", str(tree), "--fail-on", "never") == 0
    out = capsys.readouterr().out
    assert "hr/people.txt:3:6: CRITICAL SSN (regex 1.00): [SSN, 11 chars]" in out


def test_unreadable_file_makes_scan_incomplete(tree: Path, tmp_path: Path):
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    locked = tree / "locked.txt"
    locked.write_text("hello\n")
    locked.chmod(0)
    try:
        assert run("--all", str(tree), "--fail-on", "never", "-q") == 3
        assert run("--all", str(tree), "--fail-on", "never", "--allow-incomplete", "-q") == 0
    finally:
        locked.chmod(0o600)


def test_masking_inline_and_from_report(tree: Path, tmp_path: Path):
    out = tmp_path / "masked"
    report = tmp_path / "r.jsonl"
    code = run("--all", str(tree), "--mask-out", str(out), "--output", "jsonl", "--report", str(report),
               "--fail-on", "never", "-q")
    assert code == 0
    people = (out / "hr" / "people.txt").read_text()
    for secret in ("123-45-6789", "4111 1111 1111 1111", "P@ssw0rd123!", "AKIAIOSFODNN7EXAMPLE", "hunter2secret"):
        assert secret not in people
    assert "[SSN]" in people and "[PASSWORD]" in people
    assert "1234 5678 9012 3456" in people  # not a valid card, left alone
    assert (out / "hr" / "crlf.txt").read_bytes() == b"line one\r\nSSN [SSN]\r\nend\r\n"
    assert (out / "hr" / "wide.txt").read_bytes() == "﻿SSN [SSN]\n".encode("utf-16")
    assert (out / "clean.txt").read_text() == "nothing to see here\n"
    assert not (out / "image.bin").exists() and not (out / "link.txt").exists()
    assert oct((out / "hr" / "people.txt").stat().st_mode & 0o777) == "0o600"

    out2 = tmp_path / "masked2"
    assert main(["mask", "--from", str(report), "--out", str(out2), "-q"]) == 0
    assert (out2 / "hr" / "people.txt").read_text() == people

    (tree / "hr" / "people.txt").write_text(SAMPLE + "changed\n")
    out3 = tmp_path / "masked3"
    assert main(["mask", "--from", str(report), "--out", str(out3), "-q"]) == 3  # sha256 mismatch


def test_mask_out_inside_scan_root_is_refused(tree: Path):
    assert run("--all", str(tree), "--mask-out", str(tree / "masked")) == 2


# --- configuration errors -----------------------------------------------------------------------


def test_invalid_entity_type_in_config(tree: Path, tmp_path: Path, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"critical_entity_types": ["CREDIT_CARD"]}))
    assert run("--all", str(tree), "--config", str(cfg)) == 2
    assert "CREDIT_DEBIT_NUMBER" in capsys.readouterr().err


def test_legacy_config_keys_accepted(tree: Path, tmp_path: Path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({
        "max_workers": 4, "min_confidence_score": 0.9, "excluded_dirs": ["hr"],
        "critical_entity_types": ["EMAIL"], "batch_size": 25,
    }))
    assert run("--all", str(tree), "--config", str(cfg), "-q") == 0  # hr/ excluded -> clean


def test_unknown_config_key_rejected(tree: Path, tmp_path: Path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"layerz": ["regex"]}))
    assert run("--all", str(tree), "--config", str(cfg)) == 2


@pytest.mark.parametrize("argv", [["--help"], ["-h"], ["scan", "--help"]])
def test_help_shows_scan_options(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("usage: pii-scan [scan] [options] [PATH ...]")
    for text in ("--all", "--aws", "--mask-out", "--fail-on", "commands:", "exit codes:"):
        assert text in out


def test_version_and_subcommand_help(capsys):
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "pii-scan 1.1.0" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["mask", "--help"])
    assert "--from" in capsys.readouterr().out


def test_aws_flag_sets_layer_preset(tree: Path):
    from pii_scan.cli import build_parser, settings_from_args

    s = settings_from_args(build_parser().parse_args(["scan", "--all", str(tree), "--aws"]))
    assert s.layers == ("regex", "contains", "detect")
    assert settings_from_args(build_parser().parse_args(["scan", "--all", str(tree)])).layers == ("regex",)
    assert run("--all", str(tree), "--aws", "--layers", "regex") == 2


def test_show_values_refused_in_ci(tree: Path, monkeypatch):
    monkeypatch.setenv("CI", "true")
    assert run("--all", str(tree), "--show-values") == 2


def test_not_a_git_repo_without_all(tmp_path: Path, capsys):
    assert run(str(tmp_path)) == 2
    assert "--all" in capsys.readouterr().err


def test_baseline_roundtrip(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    base = tmp_path / "baseline.json"
    assert run("--all", str(tree), "--write-baseline", str(base), "-q") == 1
    assert run("--all", str(tree), "--baseline", str(base), "-q") == 0


def test_baseline_requires_key(tree: Path, tmp_path: Path):
    assert run("--all", str(tree), "--write-baseline", str(tmp_path / "b.json")) == 2


def test_cache_skips_unchanged(tree: Path, tmp_path: Path):
    cache = tmp_path / "cache.sqlite"
    r1, r2 = tmp_path / "1.jsonl", tmp_path / "2.jsonl"
    assert run("--all", str(tree), "--cache", str(cache), "--output", "jsonl", "--report", str(r1), "-q") == 1
    assert run("--all", str(tree), "--cache", str(cache), "--output", "jsonl", "--report", str(r2), "-q") == 1
    s1, s2 = records(r1)[-1], records(r2)[-1]
    assert s1["cached_files"] == 0 and s2["cached_files"] == 5
    assert s1["findings_by_type"] == s2["findings_by_type"]


# --- git changed-files mode --------------------------------------------------------------------


def test_git_changed_files_from_subdirectory(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("hello\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "sub").mkdir()
    (repo / "sub" / "café notes.txt").write_text("SSN 219-09-9999\n")
    (repo / "other.txt").write_text("SSN 219-09-9999\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "change")

    report = tmp_path / "r.jsonl"
    code = run(str(repo / "sub"), "--base", "main", "--output", "jsonl", "--report", str(report), "-q")
    assert code == 1
    paths = {r["relpath"] for r in records(report) if r["kind"] == "file"}
    assert paths == {"sub/café notes.txt"}

    assert run(str(repo), "--output", "jsonl", "--report", str(report), "-q") == 2  # no origin, no --base
