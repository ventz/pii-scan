"""Regression tests for issues found in the pre-release audit."""

import io
import json
import os
from pathlib import Path

import pytest

from pii_scan.cli import main
from pii_scan.models import FileResult, Finding, Severity, Status
from pii_scan.pipeline import Scanner, Summary
from pii_scan.sinks import JsonlSink
from pii_scan.sniff import decode, detect_encoding, encode_like

from .conftest import SAMPLE, git


def run(*args: str) -> int:
    return main([*args, "--progress", "none", "-q"])


def records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_mask_from_refuses_output_over_scanned_tree(tree: Path, tmp_path: Path):
    report = tmp_path / "r.jsonl"
    run("--all", str(tree), "--output", "jsonl", "--report", str(report), "--fail-on", "never")
    before = (tree / "hr" / "people.txt").read_text()
    assert main(["mask", "--from", str(report), "--out", str(tree), "-q"]) == 2
    assert main(["mask", "--from", str(report), "--out", str(tree / "hr"), "-q"]) == 2
    assert (tree / "hr" / "people.txt").read_text() == before


def test_match_limit_marks_file_not_scanned_and_not_masked(tmp_path: Path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "many.txt").write_text("".join(f"SSN 219-09-{1000 + i}\n" for i in range(6)))
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"limits": {"max_matches_per_rule": 5}}))
    out = tmp_path / "masked"
    report = tmp_path / "r.jsonl"
    code = run("--all", str(root), "--config", str(cfg), "--mask-out", str(out), "--output", "jsonl",
               "--report", str(report), "--fail-on", "never")
    assert code == 3
    summary = records(report)[-1]
    assert any(k.startswith("match_limit") for k in summary["not_scanned_reasons"])
    assert not (out / "many.txt").exists()


def test_mask_from_masks_baseline_suppressed_values(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    base, report, out = tmp_path / "b.json", tmp_path / "r.jsonl", tmp_path / "masked"
    run("--all", str(tree), "--write-baseline", str(base))
    assert run("--all", str(tree), "--baseline", str(base), "--output", "jsonl", "--report", str(report)) == 0
    assert any(r.get("suppressed") for r in records(report) if r["kind"] == "finding")
    assert main(["mask", "--from", str(report), "--out", str(out), "-q"]) == 0
    assert "123-45-6789" not in (out / "hr" / "people.txt").read_text()


def test_write_baseline_keeps_already_accepted_entries(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    b1, b2 = tmp_path / "b1.json", tmp_path / "b2.json"
    run("--all", str(tree), "--write-baseline", str(b1))
    run("--all", str(tree), "--baseline", str(b1), "--write-baseline", str(b2))
    assert json.loads(b1.read_text()) == json.loads(b2.read_text())


def test_cache_stores_findings_before_baseline(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    base, cache = tmp_path / "b.json", tmp_path / "c.db"
    run("--all", str(tree), "--write-baseline", str(base))
    assert run("--all", str(tree), "--baseline", str(base), "--cache", str(cache)) == 0
    assert run("--all", str(tree), "--cache", str(cache)) == 1  # findings are back without the baseline


def test_show_values_never_uses_cache(tree: Path, tmp_path: Path):
    cache = tmp_path / "c.db"
    run("--all", str(tree), "--show-values", "--cache", str(cache), "--fail-on", "never")
    assert not cache.exists()


@pytest.mark.parametrize("config", [
    {"fail_on": "hgh"},
    {"mask": {"style": "bogus"}},
    {"limits": {"workers": "x"}},
    {"severity": {"sever": ["SSN"]}},
    {"aws": {"tps_detect": 0}},
])  # fmt: skip
def test_invalid_config_values_exit_2(tree: Path, tmp_path: Path, config):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps(config))
    assert run("--all", str(tree), "--config", str(cfg)) == 2


def test_invalid_rate_flag_exits_2(tree: Path):
    assert run("--all", str(tree), "--max-tps-detect", "0") == 2


def test_git_mode_skips_symlinks_and_submodule_like_dirs(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("hello\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "link.txt").symlink_to("README.md")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "symlink")
    nested = repo / "vendor"
    nested.mkdir()
    git(nested, "init", "-q")  # untracked nested repository shows up as a directory entry
    assert run(str(repo), "--base", "main") == 0


def test_exclude_globs_apply_to_each_root(tmp_path: Path):
    for name in ("r1", "r2"):
        (tmp_path / name / "archive").mkdir(parents=True)
        (tmp_path / name / "archive" / "f.txt").write_text("SSN 219-09-9999\n")
    assert run("--all", "--exclude", "archive/**", str(tmp_path / "r1"), str(tmp_path / "r2")) == 0


def test_worker_crash_marks_file_not_scanned(tree: Path, monkeypatch):
    def boom(self, *a, **k):
        raise MemoryError("simulated")

    monkeypatch.setattr(Scanner, "_findings", boom)
    assert run("--all", str(tree), "--fail-on", "never") == 3


def test_jsonl_handles_undecodable_file_names():
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    f = Finding("/x/caf\udce9.txt", 1, 1, 1, 2, 0, 1, "SSN", Severity.CRITICAL, 1.0, "regex", "r", "[SSN]", "ab")
    sink = JsonlSink(stream)
    sink.file(FileResult("/x/caf\udce9.txt", Status.FINDINGS, relpath="caf\udce9.txt", findings=[f]))
    sink.close(Summary())
    stream.flush()
    assert b"caf\\\\udce9.txt" in stream.buffer.getvalue()


def test_baseline_matches_between_all_and_changed_modes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("hi\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "sub" / "f.txt").write_text("SSN 219-09-9999\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "add")
    monkeypatch.chdir(repo)
    assert run("--all", "sub", "--write-baseline", str(tmp_path / "b.json")) == 1
    assert run(".", "--base", "main", "--baseline", str(tmp_path / "b.json")) == 0


def test_masked_directories_are_private(tree: Path, tmp_path: Path):
    out = tmp_path / "masked"
    run("--all", str(tree), "--mask-out", str(out), "--fail-on", "never")
    assert oct((out / "hr").stat().st_mode & 0o777) == "0o700"


def test_cp1252_roundtrip_with_undefined_byte():
    raw = ("x" * 9000).encode() + "Café \x81 SSN".encode("latin-1")
    enc = detect_encoding(raw[:8192], truncated=True)
    assert enc == "utf-8"  # prefix is ASCII; decode must still round-trip
    assert encode_like(decode(raw, "cp1252"), "cp1252") == raw
    assert encode_like(decode(raw, enc), enc) == raw


def test_sample_data_counts_are_stable(tmp_path: Path):
    p = tmp_path / "s.txt"
    p.write_text(SAMPLE)
    assert run("--all", str(p)) == 1
    assert os.environ.get("PII_SCAN_HMAC_KEY") is None
