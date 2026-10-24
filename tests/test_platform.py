"""Platform file-system safety: links, junctions, cloud placeholders, owner-only files, and names
Windows can't store. Pure checks run everywhere; the Windows behavior runs on Windows CI."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pii_scan.cli import main
from pii_scan.masking import safe_output_path
from pii_scan.private import (
    extended_path,
    is_link,
    is_link_attributes,
    is_placeholder,
    is_under,
    strip_extended_prefix,
    windows_name_problem,
)
from pii_scan.sources.base import ReadError
from pii_scan.sources.fs import read_regular_file

from .conftest import SAMPLE, assert_private, requires_symlinks

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows behavior")

REPARSE = stat.FILE_ATTRIBUTE_REPARSE_POINT
IO_REPARSE_TAG_SYMLINK = 0xA000000C
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003  # junction
IO_REPARSE_TAG_DEDUP = 0x80000013  # Windows Server deduplication: real data, not a link
IO_REPARSE_TAG_CLOUD_6 = 0x9000601A  # OneDrive placeholder


def run(*args: str) -> int:
    return main([*args, "--progress", "none", "-q"])


def _st(mode=stat.S_IFREG, attributes=0, tag=0, flags=0):
    return SimpleNamespace(st_mode=mode, st_file_attributes=attributes, st_reparse_tag=tag, st_flags=flags)


# --- pure checks ---------------------------------------------------------------------------------


@pytest.mark.parametrize(("st", "expected"), [
    (_st(mode=stat.S_IFLNK), True),
    (_st(attributes=REPARSE, tag=IO_REPARSE_TAG_SYMLINK), True),
    (_st(mode=stat.S_IFDIR, attributes=REPARSE | stat.FILE_ATTRIBUTE_DIRECTORY, tag=IO_REPARSE_TAG_MOUNT_POINT), True),
    (_st(attributes=REPARSE, tag=IO_REPARSE_TAG_DEDUP), False),  # must still be read, through the filter
    (_st(attributes=REPARSE, tag=IO_REPARSE_TAG_CLOUD_6), False),
    (_st(), False),
])  # fmt: skip
def test_links_are_name_surrogates(st, expected):
    assert is_link(st) is expected


def test_dedup_reparse_point_is_not_a_link():
    assert not is_link_attributes(REPARSE, IO_REPARSE_TAG_DEDUP)
    assert is_link_attributes(REPARSE, IO_REPARSE_TAG_MOUNT_POINT)


@pytest.mark.parametrize(("st", "expected"), [
    (_st(attributes=0x400000), True),  # RECALL_ON_DATA_ACCESS (OneDrive "online only")
    (_st(attributes=0x40000), True),  # RECALL_ON_OPEN
    (_st(attributes=0x1000), True),  # OFFLINE (HSM)
    (_st(flags=0x40000000), True),  # macOS SF_DATALESS (iCloud Drive)
    (_st(attributes=REPARSE, tag=IO_REPARSE_TAG_DEDUP), False),
    (_st(), False),
])  # fmt: skip
def test_cloud_placeholders_are_detected(st, expected):
    assert is_placeholder(st) is expected


@pytest.mark.parametrize(("raw", "clean"), [
    ("\\\\?\\C:\\share\\a.txt", "C:\\share\\a.txt"),
    ("\\\\?\\UNC\\server\\share\\a.txt", "\\\\server\\share\\a.txt"),
    ("C:\\plain", "C:\\plain"),
])  # fmt: skip
def test_extended_path_prefix_is_stripped(raw, clean):
    assert strip_extended_prefix(raw) == clean


@pytest.mark.parametrize(("path", "expected"), [
    ("C:\\share\\secret.", "\\\\?\\C:\\share\\secret."),
    ("C:/share/NUL", "\\\\?\\C:\\share\\NUL"),
    ("\\\\srv\\share\\a.txt", "\\\\?\\UNC\\srv\\share\\a.txt"),
    ("notes.txt", "\\\\?\\D:\\work\\notes.txt"),
    ("\\\\?\\C:\\already", "\\\\?\\C:\\already"),
])  # fmt: skip
def test_extended_paths(path, expected):
    assert extended_path(path, "D:\\work") == expected


def test_is_under_respects_component_boundaries():
    root = os.path.join(os.sep, "data", "share")
    assert is_under(os.path.join(root, "a.txt"), root)
    assert is_under(root, root + os.sep)
    assert not is_under(os.path.join(os.sep, "data", "share-other", "a.txt"), root)


@pytest.mark.parametrize(("name", "bad"), [
    ("report.txt", False), ("con.txt.bak", True), ("CON", True), ("nul.json", True), ("COM1", True),
    ("lpt9.log", True), ("COM¹", True), ("console.txt", False), ("a:b.txt", True), ("C:evil", True),
    ("trailing.", True), ("trailing ", True), ("q?.txt", True), ("tab\tname", True), ("ok name.txt", False),
])  # fmt: skip
def test_windows_name_problems(name, bad):
    assert bool(windows_name_problem(name)) is bad


# --- Windows -------------------------------------------------------------------------------------


def _junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)


@windows_only
def test_walk_excludes_junctions(tmp_path: Path):
    root, outside = tmp_path / "share", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
    (root / "notes.txt").write_text("nothing here\n")
    _junction(root / "jump", outside)
    report = tmp_path / "r.jsonl"
    assert run("--all", str(root), "--output", "jsonl", "--report", str(report), "--fail-on", "any") == 0
    recs = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
    assert not any(r.get("kind") == "finding" for r in recs)


@windows_only
def test_read_refuses_parent_swapped_for_junction(tmp_path: Path):
    inside, outside = tmp_path / "share", tmp_path / "secret"
    inside.mkdir()
    outside.mkdir()
    (outside / "creds.txt").write_text("aws_secret_access_key = x\n")
    _junction(inside / "swapped", outside)
    with pytest.raises(ReadError) as exc:
        read_regular_file(str(inside / "swapped" / "creds.txt"), 1000, root=os.path.realpath(inside))
    assert exc.value.reason == "outside_root"


@windows_only
def test_report_cache_and_baseline_are_private(tree: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    report, cache, baseline = tmp_path / "r.jsonl", tmp_path / "c.sqlite", tmp_path / "b.json"
    run("--all", str(tree), "--output", "jsonl", "--report", str(report), "--cache", str(cache),
        "--write-baseline", str(baseline), "--fail-on", "never")  # fmt: skip
    for path in (report, cache, baseline):
        assert_private(path, 0o600)


@windows_only
@requires_symlinks
def test_report_through_symlink_is_refused_without_truncating(tree: Path, tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n")
    link = tmp_path / "report.jsonl"
    link.symlink_to(victim)
    assert run("--all", str(tree), "--output", "jsonl", "--report", str(link)) == 2
    assert victim.read_text() == "keep me\n"  # never truncated


@windows_only
def test_reserved_output_names_are_refused(tmp_path: Path):
    for rel in ("hr/CON.txt", "hr/a:b.txt", "hr/trailing.", "aux/notes.txt"):
        with pytest.raises(ValueError):
            safe_output_path(tmp_path / "out", rel)
    assert safe_output_path(tmp_path / "out", "hr/notes.txt").name == "notes.txt"


@windows_only
def test_masked_tree_is_private(tmp_path: Path):
    root = tmp_path / "share"
    (root / "hr").mkdir(parents=True)
    (root / "hr" / "people.txt").write_text(SAMPLE)
    out = tmp_path / "masked"
    assert run("--all", str(root), "--mask-out", str(out), "--fail-on", "never") == 0
    for path in (out, out / "hr", out / "hr" / "people.txt"):
        assert_private(path, 0o700 if path.is_dir() else 0o600)


# --- placeholders and devices, end to end ------------------------------------------------------


def test_placeholder_files_are_not_scanned_or_masked(tmp_path: Path, monkeypatch):
    root = tmp_path / "share"
    root.mkdir()
    (root / "cloud.txt").write_text(SAMPLE)
    (root / "local.txt").write_text("nothing here\n")
    monkeypatch.setattr("pii_scan.sources.fs.is_placeholder",
                        lambda st: stat.S_ISREG(st.st_mode) and st.st_size > 100)  # fmt: skip
    report, out = tmp_path / "r.jsonl", tmp_path / "masked"
    code = run("--all", str(root), "--output", "jsonl", "--report", str(report), "--mask-out", str(out))
    assert code == 3
    recs = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
    summary = next(r for r in recs if r["kind"] == "summary")
    assert summary["not_scanned_reasons"] == {"offline_placeholder": 1}
    assert not (out / "cloud.txt").exists() and (out / "local.txt").exists()


def test_placeholder_changed_files_are_not_scanned(tmp_path: Path, monkeypatch):
    from .conftest import git

    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("base\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    (repo / "cloud.txt").write_text(SAMPLE)
    monkeypatch.setattr("pii_scan.sources.git.is_placeholder", lambda st: st.st_size > 100)
    assert run(str(repo), "--base", "main", "--fail-on", "never") == 3


def test_report_to_null_device(tree: Path):
    assert run("--all", str(tree), "--output", "jsonl", "--report", os.devnull, "--fail-on", "never") == 0


def test_cache_notices_an_edit_with_restored_mtime(tmp_path: Path):
    # Same size, old mtime put back: only ctime (POSIX) or NTFS ChangeTime (Windows) reveals it.
    root = tmp_path / "share"
    root.mkdir()
    target = root / "notes.txt"
    clean = "reference 000000000000\n"
    secret = "ssn is 123-45-6789 ok\n"
    secret += " " * (len(clean) - len(secret))
    target.write_text(clean)
    cache = tmp_path / "cache.sqlite"
    assert run("--all", str(root), "--cache", str(cache), "--fail-on", "any") == 0
    before = target.stat()
    target.write_text(secret)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert target.stat().st_size == before.st_size
    assert run("--all", str(root), "--cache", str(cache), "--fail-on", "any") == 1


@windows_only
def test_outputs_are_born_private(tree: Path, tmp_path: Path, monkeypatch):
    # With the after-the-fact ACL calls disabled, new outputs must still be private: they are
    # created with the private ACL, so no other user can open them in between.
    monkeypatch.setattr("pii_scan.private.make_private", lambda *a, **k: None)
    monkeypatch.setattr("pii_scan.private.make_private_fd", lambda *a, **k: None)
    monkeypatch.setattr("pii_scan.cli.make_private_fd", lambda *a, **k: None)
    monkeypatch.setenv("PII_SCAN_HMAC_KEY", "0123456789abcdef-test-key")
    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(["icacls", str(work), "/grant", "*S-1-5-32-545:(OI)(CI)R"], check=True, capture_output=True)
    report, baseline, out = work / "r.jsonl", work / "b.json", work / "masked"
    run("--all", str(tree), "--output", "jsonl", "--report", str(report), "--write-baseline", str(baseline),
        "--mask-out", str(out), "--fail-on", "never")  # fmt: skip
    for path in (report, baseline, out, out / "hr", out / "hr" / "people.txt"):
        assert_private(path, 0o700 if path.is_dir() else 0o600)


@windows_only
def test_same_filesystem_still_descends_on_windows(tmp_path: Path):
    root = tmp_path / "share"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.txt").write_text(SAMPLE)
    report = tmp_path / "r.jsonl"
    run("--all", str(root), "--same-filesystem", "--output", "jsonl", "--report", str(report), "--fail-on", "never")
    recs = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
    assert any(r["kind"] == "finding" for r in recs)
    assert not any(r.get("reason") == "different filesystem" for r in recs)


@windows_only
def test_names_win32_would_rewrite_are_read_exactly(tmp_path: Path):
    root = tmp_path / "share"
    root.mkdir()
    exact = "\\\\?\\" + str(root)
    with open(exact + "\\secret.", "w") as fh:  # only creatable through the \\?\ form
        fh.write("ssn 123-45-6789\n")
    (root / "secret").write_text("nothing here\n")
    data = read_regular_file(str(root / "secret."), 1000, root=str(root))
    assert b"123-45-6789" in data


@windows_only
def test_report_through_junction_is_refused(tree: Path, tmp_path: Path):
    # Junctions only point at directories, and a directory can't be opened as a report either way,
    # so this checks the outcome (refused, nothing written), not which check refused it. Links to
    # files are covered by test_report_through_symlink_is_refused_without_truncating.
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    _junction(tmp_path / "report.jsonl", target_dir)
    assert run("--all", str(tree), "--output", "jsonl", "--report", str(tmp_path / "report.jsonl")) == 2
    assert list(target_dir.iterdir()) == []


# --- review fixes: paths, errors, and outputs ----------------------------------------------------


@pytest.mark.parametrize(("path", "expected"), [
    ("..\\c.sqlite", "\\\\?\\D:\\work\\c.sqlite"),
    ("../b.json", "\\\\?\\D:\\work\\b.json"),
    (".\\a\\..\\notes.txt", "\\\\?\\D:\\work\\sub\\notes.txt"),
    ("C:\\share\\x\\..\\secret.", "\\\\?\\C:\\share\\secret."),  # trailing dot kept
    ("C:\\share\\secret ", "\\\\?\\C:\\share\\secret "),  # trailing space kept
    ("\\\\srv\\share\\a\\..\\b.txt", "\\\\?\\UNC\\srv\\share\\b.txt"),
    ("\\data\\c.sqlite", "\\\\?\\D:\\data\\c.sqlite"),  # rooted on the current drive
    ("D:notes.txt", "\\\\?\\D:\\work\\sub\\notes.txt"),  # drive-relative, current drive
    ("\\\\.\\NUL", "\\\\.\\NUL"),  # device namespace: unchanged
    ("\\\\srv\\share", "\\\\?\\UNC\\srv\\share"),
    ("//?/C:/x", "\\\\?\\C:\\x"),  # forward-slash forms of the exact and device prefixes
    ("//./NUL", "\\\\.\\NUL"),
])  # fmt: skip
def test_extended_paths_resolve_dot_dot(path, expected):
    # \\?\ takes ".." literally, so it is resolved first (lexically, keeping trailing dots/spaces).
    assert extended_path(path, "D:\\work\\sub") == expected


def test_extended_path_with_extended_cwd():
    assert extended_path("a.txt", "\\\\?\\D:\\work") == "\\\\?\\D:\\work\\a.txt"
    assert extended_path("a.txt", "\\\\?\\UNC\\srv\\share") == "\\\\?\\UNC\\srv\\share\\a.txt"


def test_drive_relative_path_on_another_drive_is_refused():
    with pytest.raises(OSError):
        extended_path("C:notes.txt", "D:\\work")


def _repo_with_change(tmp_path: Path, content: str = "nothing here\n") -> Path:
    from .conftest import git

    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("base\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    (repo / "changed.txt").write_text(content)
    return repo


def _failing_change_marker(exc: OSError):
    def change_marker(path, st, precise):
        if precise and path.endswith("changed.txt"):
            raise exc
        return max(st.st_mtime_ns, st.st_ctime_ns)

    return change_marker


def test_changed_file_that_cannot_be_examined_is_not_scanned(tmp_path: Path, monkeypatch):
    # Access denied or a sharing violation while reading the change time (Windows, with --cache)
    # must not drop the file silently: the run is incomplete.
    repo = _repo_with_change(tmp_path)
    monkeypatch.setattr("pii_scan.sources.git.change_marker", _failing_change_marker(PermissionError(13, "denied")))
    report = tmp_path / "r.jsonl"
    code = run(str(repo), "--base", "main", "--cache", str(tmp_path / "c.sqlite"), "--output", "jsonl",
               "--report", str(report))  # fmt: skip
    assert code == 3
    lines = report.read_text(encoding="utf-8").splitlines()
    summary = next(r for r in map(json.loads, lines) if r["kind"] == "summary")
    assert summary["not_scanned_reasons"] == {"stat": 1}


def test_changed_file_deleted_since_the_diff_is_skipped(tmp_path: Path, monkeypatch):
    repo = _repo_with_change(tmp_path)
    monkeypatch.setattr("pii_scan.sources.git.change_marker", _failing_change_marker(FileNotFoundError(2, "gone")))
    assert run(str(repo), "--base", "main", "--cache", str(tmp_path / "c.sqlite")) == 0


def test_changed_file_lstat_error_is_not_scanned(tmp_path: Path, monkeypatch):
    repo = _repo_with_change(tmp_path)
    real_lstat = Path.lstat

    def lstat(self):
        if self.name == "changed.txt":
            raise PermissionError(13, "denied")
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", lstat)
    if sys.platform == "win32":
        monkeypatch.setattr("pii_scan.sources.git.os.lstat",
                            lambda p, _real=os.lstat: lstat(Path(p)) if p.endswith("changed.txt") else _real(p))
    assert run(str(repo), "--base", "main") == 3


def test_is_gone_only_for_missing_files():
    from pii_scan.private import is_gone

    assert is_gone(FileNotFoundError(2, "gone"))
    missing_path = OSError(22, "x")
    missing_path.winerror = 3  # ERROR_PATH_NOT_FOUND
    assert is_gone(missing_path)
    assert not is_gone(PermissionError(13, "denied"))
    assert not is_gone(OSError(5, "sharing violation"))


def _failing_change_time(path, st):
    raise PermissionError(13, "denied")


def test_walk_change_time_error_is_not_scanned(tmp_path: Path, monkeypatch):
    root = tmp_path / "share"
    root.mkdir()
    (root / "locked.txt").write_text("nothing here\n")
    monkeypatch.setattr("pii_scan.sources.fs.change_time_ns", _failing_change_time)
    cache = tmp_path / "c.sqlite"
    assert run("--all", str(root), "--cache", str(cache)) == 3
    assert run("--all", str(root / "locked.txt"), "--cache", str(cache)) == 3  # a file named directly


def test_excluded_file_is_not_opened_for_its_change_time(tmp_path: Path, monkeypatch):
    root = tmp_path / "share"
    root.mkdir()
    (root / "locked.log").write_text("nothing here\n")
    (root / "notes.txt").write_text("nothing here\n")
    opened = []

    def change_time(path, st):
        opened.append(path)
        if path.endswith("locked.log"):
            raise PermissionError(13, "denied")
        return st.st_mtime_ns

    monkeypatch.setattr("pii_scan.sources.fs.change_time_ns", change_time)
    assert run("--all", str(root), "--cache", str(tmp_path / "c.sqlite"), "--exclude", "*.log") == 0
    assert not any(p.endswith("locked.log") for p in opened)


def test_git_runs_with_no_transport_allowed(tmp_path: Path, monkeypatch):
    import pii_scan.sources.git as gitsrc

    repo = _repo_with_change(tmp_path)
    envs = []
    real_run = subprocess.run

    def spy(*args, **kwargs):
        envs.append(kwargs.get("env"))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(gitsrc.subprocess, "run", spy)
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "ext:file")  # inherited value must not survive
    assert run(str(repo), "--base", "main") == 0
    assert envs and all(env["GIT_ALLOW_PROTOCOL"] == "none" for env in envs)


def test_report_left_untouched_when_it_cannot_be_made_private(tree: Path, tmp_path: Path, monkeypatch):
    report = tmp_path / "r.jsonl"
    report.write_text("previous report\n")

    def refuse(fd, mode):
        raise PermissionError(1, "not permitted")

    monkeypatch.setattr("pii_scan.cli.make_private_fd", refuse)
    assert run("--all", str(tree), "--output", "jsonl", "--report", str(report)) == 2
    assert report.read_text() == "previous report\n"  # never emptied


def test_existing_report_is_overwritten(tree: Path, tmp_path: Path):
    report = tmp_path / "r.jsonl"
    report.write_text("x" * 100_000 + "\n")
    assert run("--all", str(tree), "--output", "jsonl", "--report", str(report), "--fail-on", "never") == 0
    recs = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
    assert recs[-1]["kind"] == "summary"


def test_text_output_escapes_control_characters_in_rule_ids(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_text("id EMP-123456\n")
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{"id": "emp\x1b[2J\r", "pattern": "EMP-[0-9]{6}"}]}))
    report = tmp_path / "r.txt"
    run("--all", str(root), "--custom-regex", str(rules), "--report", str(report), "--fail-on", "never")
    text = report.read_text(encoding="utf-8")
    assert "EMP" in text or "emp" in text
    assert "\x1b" not in text and "\r" not in text


@windows_only
def test_relative_dot_dot_paths_work_on_windows(tree: Path, tmp_path: Path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    code = run("--all", str(tree), "--cache", "..\\c.sqlite", "--output", "jsonl", "--report", "..\\r.jsonl",
               "--fail-on", "never")  # fmt: skip
    assert code == 0
    assert (tmp_path / "c.sqlite").exists() and (tmp_path / "r.jsonl").exists()


@windows_only
def test_directory_with_trailing_dot_is_listed_exactly(tmp_path: Path):
    # A plain Win32 path drops the trailing dot, so listing "dir." would list its sibling "dir".
    root = tmp_path / "share"
    (root / "dir").mkdir(parents=True)
    (root / "dir" / "plain.txt").write_text("nothing here\n")
    exact = "\\\\?\\" + str(root / "dir.")
    os.mkdir(exact)
    with open(exact + "\\hidden.txt", "w") as fh:
        fh.write("ssn 123-45-6789\n")
    report = tmp_path / "r.jsonl"
    run("--all", str(root), "--output", "jsonl", "--report", str(report), "--fail-on", "never")
    recs = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
    assert any(r["kind"] == "finding" and r["relpath"] == "dir./hidden.txt" for r in recs)


@pytest.mark.parametrize(("content", "unreadable", "expected"), [
    ("nothing here\n", False, "true"),
    ("ssn 123-45-6789\n", False, "true"),
    ("ssn 123-45-6789\n", True, "false"),  # exit code 1, but a file was not scanned
])  # fmt: skip
def test_github_output_says_whether_the_scan_was_complete(tmp_path: Path, monkeypatch, content, unreadable, expected):
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_text(content)
    if unreadable:
        (root / "big.txt").write_text("x" * 2000)
    output = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    code = run("--all", str(root), "--github", "--max-file-size", "1000")
    assert code == (1 if "ssn" in content else 0)
    assert output.read_text(encoding="utf-8") == f"complete={expected}\n"


def test_github_output_incomplete_even_when_allowed(tmp_path: Path, monkeypatch):
    root = tmp_path / "share"
    root.mkdir()
    (root / "big.txt").write_text("x" * 2000)
    output = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert run("--all", str(root), "--github", "--max-file-size", "1000", "--allow-incomplete") == 0
    assert output.read_text(encoding="utf-8") == "complete=false\n"


def test_github_output_incomplete_when_sarif_is_truncated(tmp_path: Path, monkeypatch):
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_text("ssn 123-45-6789\nssn 123-45-6780\nssn 123-45-6781\n")
    monkeypatch.setattr("pii_scan.sinks.SARIF_MAX_RESULTS", 2)
    output, report = tmp_path / "github_output", tmp_path / "r.sarif"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert run("--all", str(root), "--github", "--output", "sarif", "--report", str(report)) == 1
    assert json.loads(report.read_text(encoding="utf-8"))["runs"][0]["properties"]["droppedResults"] >= 1
    assert output.read_text(encoding="utf-8") == "complete=false\n"


def test_github_output_not_written_when_report_fails(tmp_path: Path, monkeypatch):
    # The report sink closes first; if it fails, `complete` must never say true.
    root = tmp_path / "share"
    root.mkdir()
    (root / "a.txt").write_text("nothing here\n")

    def broken(self, summary):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("pii_scan.sinks.SarifSink.close", broken)
    output, report = tmp_path / "github_output", tmp_path / "r.sarif"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert run("--all", str(root), "--github", "--output", "sarif", "--report", str(report)) == 2
    assert not output.exists()
