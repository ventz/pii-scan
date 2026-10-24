"""Regression tests for the 1.1.1 hardening: strict config and rule types, mask --from input
checks, git config from worktrees and submodules, and RE2-only custom rules under
--restricted-config."""

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from pii_scan import cli
from pii_scan.cli import main
from pii_scan.detectors.aws import AwsSettings
from pii_scan.models import Span

from .conftest import git

needs_re2 = pytest.mark.skipif(importlib.util.find_spec("re2") is None, reason="google-re2 not installed")


def run(*args: str) -> int:
    return main([*args, "--progress", "none", "-q"])


# --- config value types --------------------------------------------------------------------------


@pytest.mark.parametrize("config", [
    {"mask": {"findings_only": "false"}},  # bool("false") is True: must not silently turn the option on
    {"exclude": {"replace_defaults": "false", "dirs": ["x"]}},
    {"aws": {"tps_detect": "40"}},  # used to crash with TypeError (exit 1, read as "findings")
    {"aws": {"max_attempts": "8"}},
    {"aws": {"max_attempts": 0}},
    {"aws": {"endpoint_url": "http://comprehend.example"}},
    {"limits": {"workers": 4.7}},
    {"limits": {"workers": True}},
    {"min_confidence": True},
    {"fail_on": 1},
    {"validation_patterns": {"SSN": "("}},
    {"custom_rules": ["rules.json"]},
    {"exclude": {"dirs": [None, 5, True]}},  # list items used to go through str()
    {"excluded_dirs": [["nested"]]},
    {"fail_on": None},  # an explicit null used to mean "not set"
    {"exclude": None},
    {"version": 2},
    {"version": "1"},
])  # fmt: skip
def test_wrongly_typed_config_values_exit_2(tree: Path, tmp_path: Path, config):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps(config))
    assert run("--all", str(tree), "--config", str(cfg), "--fail-on", "never") == 2


def test_non_finite_rate_flag_exits_2(tree: Path):
    assert run("--all", str(tree), "--max-tps-contains", "nan", "--fail-on", "never") == 2


def test_example_config_still_loads(tree: Path):
    example = Path(__file__).resolve().parents[1] / "config.json"
    assert run("--all", str(tree), "--config", str(example), "--fail-on", "never") == 0


def test_every_aws_setting_has_a_type():
    from pii_scan.settings import _AWS_TYPES

    assert set(_AWS_TYPES) == set(AwsSettings.__dataclass_fields__)


def test_crash_exits_2_never_1(tree: Path, monkeypatch):
    def boom(_args):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(cli, "cmd_scan", boom)
    assert run("--all", str(tree)) == 2


# --- custom rule file types ----------------------------------------------------------------------


@pytest.mark.parametrize("rules", [
    {"rules": 5},  # used to crash with TypeError (exit 1)
    {"rules": [{"id": "x", "pattern": "EMP-1", "severity": 5}]},  # used to crash with AttributeError
    {"rules": [{"id": "x", "pattern": "EMP-(1)", "group": -1}]},  # used to pass, then fail every match
    {"rules": [{"id": "x", "pattern": "EMP-(1)", "group": "1"}]},
    {"rules": [{"id": "x", "pattern": "EMP-(1)", "group": True}]},
    {"rules": [{"id": 5, "pattern": "EMP-1"}]},
    {"rules": [{"id": "x", "pattern": "EMP-1", "type": 7}]},
    {"rules": [{"id": "x", "pattern": "EMP-1", "label": "typo"}]},
])  # fmt: skip
def test_wrongly_typed_custom_rules_exit_2(tree: Path, tmp_path: Path, rules):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    assert run("--all", str(tree), "--custom-regex", str(path), "--fail-on", "never") == 2


def test_shipped_custom_rules_example_still_loads(tree: Path):
    example = Path(__file__).resolve().parents[1] / "custom_regex_patterns.json"
    assert run("--all", str(tree), "--custom-regex", str(example), "--fail-on", "never") == 0


# --- mask --from input -----------------------------------------------------------------------------


def _report(tmp_path: Path, data: bytes, *, file_overrides: dict | None = None, findings=()) -> Path:
    src = tmp_path / "data"
    src.mkdir(exist_ok=True)
    target = src / "notes.txt"
    target.write_bytes(data)
    file_rec = {"kind": "file", "schema": 1, "path": str(target), "relpath": "notes.txt", "status": "findings",
                "reason": "", "size": len(data), "encoding": "utf-8", "sha256": hashlib.sha256(data).hexdigest()}
    file_rec.update(file_overrides or {})
    lines = [json.dumps(file_rec)]
    lines += [json.dumps({"kind": "finding", "path": str(target), "score": 0.9, "detector": "comprehend", **f})
              for f in findings]
    report = tmp_path / "r.jsonl"
    report.write_text("\n".join(lines) + "\n")
    return report


def _mask(report: Path, out: Path, *extra: str) -> int:
    return main(["mask", "--from", str(report), "--out", str(out), "-q", *extra])


@pytest.mark.parametrize("overrides", [
    {"size": None},
    {"size": -1},
    {"sha256": 7},
    {"sha256": "z" * 64},
    {"encoding": "rot13"},
    {"relpath": None},
])  # fmt: skip
def test_mask_from_rejects_malformed_file_records(tmp_path: Path, overrides):
    report = _report(tmp_path, b"hello\n", file_overrides=overrides)
    assert _mask(report, tmp_path / "out") == 2


@pytest.mark.parametrize("finding", [
    {"start": 0, "type": "NAME"},  # no "end"
    {"start": 3, "end": 3, "type": "NAME"},
    {"start": True, "end": 4, "type": "NAME"},
    {"start": -1, "end": 4, "type": "NAME"},
    {"start": 0, "end": 4, "type": "NAME", "score": "high"},
    {"start": 0, "end": 4, "type": 5},
])  # fmt: skip
def test_mask_from_rejects_malformed_finding_records(tmp_path: Path, finding):
    report = _report(tmp_path, b"hello\n", findings=[finding])
    assert _mask(report, tmp_path / "out") == 2


def test_mask_from_rejects_non_object_lines(tmp_path: Path):
    report = tmp_path / "r.jsonl"
    report.write_text('["not", "a", "record"]\n')
    assert _mask(report, tmp_path / "out") == 2


def test_mask_from_refuses_findings_past_end_of_file(tmp_path: Path):
    report = _report(tmp_path, b"short text\n", findings=[{"start": 50, "end": 60, "type": "NAME"}])
    out = tmp_path / "out"
    assert _mask(report, out) == 3
    assert not (out / "notes.txt").exists()


def test_mask_from_verifies_no_value_is_left(tmp_path: Path):
    # The report marks only the first of two occurrences: writing the copy would leak the second.
    data = b"Jonathan Smithers called. Later Jonathan Smithers called again.\n"
    report = _report(tmp_path, data, findings=[{"start": 0, "end": 17, "type": "NAME"}])
    out = tmp_path / "out"
    assert _mask(report, out) == 3
    assert not (out / "notes.txt").exists()


def test_mask_from_writes_when_every_occurrence_is_masked(tmp_path: Path):
    data = b"Jonathan Smithers called. Later Jonathan Smithers called again.\n"
    report = _report(tmp_path, data, findings=[{"start": 0, "end": 17, "type": "NAME"},
                                                {"start": 32, "end": 49, "type": "NAME"}])  # fmt: skip
    out = tmp_path / "out"
    assert _mask(report, out) == 0
    assert (out / "notes.txt").read_text() == "[NAME] called. Later [NAME] called again.\n"


def test_mask_from_applies_custom_regex(tmp_path: Path):
    report = _report(tmp_path, b"badge EMP-123456 issued\n")
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{"id": "emp", "pattern": r"EMP-\d{6}"}]}))
    out = tmp_path / "out"
    assert _mask(report, out, "--custom-regex", str(rules)) == 0
    assert (out / "notes.txt").read_text() == "badge [CUSTOM:emp] issued\n"


def test_leak_check_covers_values_inside_merged_regions():
    from pii_scan.masking import verify_masked

    # NAME and EMAIL overlap and merge into one region; a second, unflagged copy of the name must
    # still be caught even though the merged region's text never appears again.
    text = "Jonathan Smithers <js@example.com> ... Jonathan Smithers"
    spans = [Span(0, 17, "NAME", 0.9, "comprehend"), Span(10, 34, "EMAIL", 1.0, "regex")]
    masked = "[EMAIL] ... Jonathan Smithers"
    with pytest.raises(ValueError, match="still present"):
        verify_masked(text, spans, masked)


def test_known_encodings_cover_detection_results():
    from pii_scan.sniff import ENCODINGS, detect_encoding

    samples = [b"", b"plain", "café".encode(), "café".encode("cp1252"), "﻿x".encode(),
               "x".encode("utf-16"), "x".encode("utf-32"), "hello world!".encode("utf-16-le"),
               "hello world!".encode("utf-16-be")]  # fmt: skip
    found = {detect_encoding(s) for s in samples} - {None}
    assert found <= ENCODINGS
    assert {"utf-16le", "utf-16be", "cp1252", "utf-8-sig"} <= found


# --- git: config from linked worktrees and submodules -------------------------------------------


def test_git_mode_refuses_filter_in_linked_worktree_config(tmp_path: Path):
    main_repo, worktree = tmp_path / "main", tmp_path / "wt"
    main_repo.mkdir()
    git(main_repo, "init", "-q", "-b", "main")
    (main_repo / "a.txt").write_text("base\n")
    git(main_repo, "add", ".")
    git(main_repo, "commit", "-q", "-m", "base")
    git(main_repo, "worktree", "add", "-q", str(worktree), "-b", "feature")
    marker = tmp_path / "pwned"
    git(worktree, "config", "extensions.worktreeConfig", "true")
    git(worktree, "config", "--worktree", "filter.x.clean", f"touch '{marker.as_posix()}'; cat")
    (worktree / ".gitattributes").write_text("* filter=x\n")
    (worktree / "b.txt").write_text("changed\n")
    assert run(str(worktree), "--base", "main") == 2
    assert not marker.exists()


@pytest.mark.parametrize("trust", [False, True])
def test_git_mode_never_runs_a_submodule_filter(tmp_path: Path, trust: bool):
    lib, parent = tmp_path / "lib", tmp_path / "parent"
    lib.mkdir()
    git(lib, "init", "-q", "-b", "main")
    (lib / "f.txt").write_text("v1\n")
    git(lib, "add", ".")
    git(lib, "commit", "-q", "-m", "lib")
    parent.mkdir()
    git(parent, "init", "-q", "-b", "main")
    (parent / "a.txt").write_text("base\n")
    git(parent, "add", ".")
    git(parent, "commit", "-q", "-m", "base")
    git(parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(lib), "lib")
    git(parent, "commit", "-q", "-m", "submodule")
    marker = tmp_path / "pwned"
    # The submodule's own config is not repository config of the parent, so only skipping
    # submodules keeps git from running this filter while it checks whether "lib" changed.
    git(parent / "lib", "config", "filter.x.clean", f"touch '{marker.as_posix()}'; cat")
    (parent / "lib" / ".gitattributes").write_text("* filter=x\n")
    (parent / "lib" / "f.txt").write_text("v2\n")  # same size: git must hash it, which runs the filter
    (parent / "b.txt").write_text("new\n")
    args = [str(parent), "--base", "main", "--fail-on", "never"] + (["--trust-repo"] if trust else [])
    assert run(*args) == 0
    assert not marker.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="a shell-script git only runs on POSIX")
def test_git_from_relative_path_entry_is_never_run(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("hi\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    marker = tmp_path / "pwned"
    fake = repo / "git"
    fake.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", os.pathsep.join([".", os.environ["PATH"]]))
    run(".", "--base", "main", "--fail-on", "never")
    assert not marker.exists()


def test_git_is_never_taken_from_the_repository(tmp_path: Path, monkeypatch):
    from pii_scan.sources.git import _git_executable

    repo = tmp_path / "repo"
    repo.mkdir()
    fake = repo / ("git.exe" if sys.platform == "win32" else "git")
    fake.write_bytes(b"")
    fake.chmod(0o755)
    real = _git_executable(repo)
    monkeypatch.setenv("PATH", os.pathsep.join([".", str(repo), os.environ["PATH"]]))
    monkeypatch.chdir(repo)
    found = _git_executable(repo)
    assert Path(found).resolve() != fake.resolve()
    assert Path(found).resolve() == Path(real).resolve()


def test_git_mode_ignores_operator_global_config(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text('[filter "lfs"]\n\tclean = something-custom %f\n')
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("hi\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    assert run(str(repo), "--base", "main") == 0


# --- custom rules under --restricted-config ------------------------------------------------------


def _rules(directory: Path, pattern: str) -> Path:
    path = directory / "rules.json"
    path.write_text(json.dumps({"rules": [{"id": "emp", "pattern": pattern, "type": "CUSTOM:EMP"}]}))
    return path


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch) -> Path:
    """Untrusted rules files must live under the working directory, as in the GitHub Action."""
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.chdir(ws)
    return ws


def _restricted(tree: Path, *args: str) -> int:
    return run("--all", str(tree), "--restricted-config", "--fail-on", "never", *args)


@needs_re2
def test_restricted_custom_rule_must_be_re2(tree: Path, workspace: Path):
    rules = _rules(workspace, r"EMP-(?=\d)\d{6}")  # lookahead: Python re only
    assert _restricted(tree, "--custom-regex", str(rules)) == 2
    assert run("--all", str(tree), "--custom-regex", str(rules), "--fail-on", "never") == 0  # trusted: falls back


@needs_re2
def test_restricted_custom_rule_in_re2_syntax_is_accepted(tree: Path, workspace: Path):
    assert _restricted(tree, "--custom-regex", str(_rules(workspace, r"EMP-\d{6}"))) == 0


@needs_re2
def test_restricted_config_custom_rules_and_legacy_patterns_must_be_re2(tree: Path, workspace: Path):
    _rules(workspace, r"EMP-(?=\d)\d{6}")
    cfg = workspace / "c.json"
    cfg.write_text(json.dumps({"custom_rules": "rules.json"}))
    assert _restricted(tree, "--config", str(cfg)) == 2
    cfg.write_text(json.dumps({"regex_patterns": {"emp": r"EMP-(?=\d)\d{6}"}}))
    assert _restricted(tree, "--config", str(cfg)) == 2
    cfg.write_text(json.dumps({"regex_patterns": {"emp": r"EMP-\d{6}"}}))
    assert _restricted(tree, "--config", str(cfg)) == 0


@needs_re2
def test_restricted_rules_file_outside_workspace_is_refused(tree: Path, tmp_path: Path, workspace: Path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    assert _restricted(tree, "--custom-regex", str(_rules(outside, r"EMP-\d{6}"))) == 2


@needs_re2
def test_restricted_rule_count_and_length_are_capped(tree: Path, workspace: Path):
    path = workspace / "rules.json"
    path.write_text(json.dumps({"rules": [{"id": f"r{i}", "pattern": f"EMP{i}"} for i in range(201)]}))
    assert _restricted(tree, "--custom-regex", str(path)) == 2
    assert _restricted(tree, "--custom-regex", str(_rules(workspace, "E" * 1001))) == 2


def test_restricted_custom_rules_need_re2_installed(tree: Path, workspace: Path, monkeypatch):
    monkeypatch.setitem(sys.modules, "re2", None)  # import re2 -> ImportError
    rules = _rules(workspace, r"EMP-\d{6}")
    assert _restricted(tree, "--custom-regex", str(rules)) == 2
    assert run("--all", str(tree), "--custom-regex", str(rules), "--fail-on", "never") == 0


@needs_re2
def test_re2_rule_scans_file_with_undecodable_byte(tmp_path: Path):
    # The invalid byte sits after the 8 KB sniff window, so the file decodes as UTF-8 with one lone
    # surrogate, which google-re2 can't encode. The file must still be scanned, with exact offsets.
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_bytes(b"id EMP-123456 here\n" + b"x" * 9000 + b"\n\xff EMP-654321\n")
    rules = _rules(tmp_path, r"EMP-\d{6}")
    report = tmp_path / "r.jsonl"
    code = run("--all", str(root), "--custom-regex", str(rules), "--output", "jsonl", "--report", str(report))
    assert code == 1
    recs = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
    starts = sorted(r["start"] for r in recs if r["kind"] == "finding" and r["type"] == "CUSTOM:EMP")
    assert starts == [3, 19 + 9000 + 1 + 2]


@pytest.mark.parametrize("trust", [False, True])
def test_git_mode_never_fetches_missing_objects(tmp_path: Path, trust: bool):
    # A partial clone whose repository config allows the "ext::" transport: an on-demand fetch of a
    # missing blob during the diff would run the command in the remote URL.
    origin, clone = tmp_path / "origin", tmp_path / "clone"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    (origin / "f.txt").write_text("v1\n")
    git(origin, "add", ".")
    git(origin, "commit", "-q", "-m", "one")
    (origin / "f.txt").write_text("v2\n")
    git(origin, "commit", "-q", "-am", "two")
    git(origin, "config", "uploadpack.allowFilter", "true")
    git(tmp_path, "clone", "-q", "--filter=blob:none", "--no-checkout", origin.as_uri(), str(clone))
    git(clone, "-c", "protocol.file.allow=always", "checkout", "-q", "main")
    marker = tmp_path / "pwned"
    git(clone, "config", "protocol.ext.allow", "always")
    git(clone, "config", "remote.origin.url", f"ext::sh -c touch% {marker.as_posix()}")
    (clone / "f.txt").write_text("local\n")
    args = [str(clone), "--base", "HEAD~1", "--fail-on", "never"] + (["--trust-repo"] if trust else [])
    assert run(*args) == 2  # refused (repository config) or incomplete enumeration: never silently clean
    assert not marker.exists()


def test_git_mode_refuses_directory_laid_out_like_a_bare_repository(tmp_path: Path):
    tree = tmp_path / "tree"
    tree.mkdir()
    git(tmp_path, "init", "-q", "--bare", str(tree))
    marker = tmp_path / "pwned"
    git(tree, "config", "core.bare", "false")
    git(tree, "config", "core.worktree", ".")
    git(tree, "config", "filter.x.clean", f"touch '{marker.as_posix()}'; cat")
    (tree / ".gitattributes").write_text("* filter=x\n")
    (tree / "notes.txt").write_text("hello\n")
    for trust in ([], ["--trust-repo"]):
        assert run(str(tree), "--base", "HEAD", *trust) == 2
    assert not marker.exists()
