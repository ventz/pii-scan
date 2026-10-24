import functools
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Synthetic values only. AWS keys are the documented AWS example keys.
SAMPLE = """Name: John Doe
Email: john.doe@example.com
SSN: 123-45-6789
Credit Card: 4111 1111 1111 1111
Not a card: 1234 5678 9012 3456
password = "P@ssw0rd123!"
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
MongoDB: mongodb://user:hunter2secret@mongodb0.example.com:27017/admin
"""


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    for var in ("CI", "GITHUB_ACTIONS", "GITHUB_BASE_REF", "PII_SCAN_HMAC_KEY", "GITHUB_STEP_SUMMARY",
                "GITHUB_OUTPUT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "share"
    (root / "hr").mkdir(parents=True)
    (root / "node_modules").mkdir()
    (root / "hr" / "people.txt").write_text(SAMPLE, encoding="utf-8")
    (root / "hr" / "crlf.txt").write_bytes(b"line one\r\nSSN 078-05-1120\r\nend\r\n")
    (root / "hr" / "legacy.txt").write_bytes("Café owner SSN 219-09-9999\n".encode("cp1252"))
    (root / "hr" / "wide.txt").write_bytes("﻿SSN 219-09-9999\n".encode("utf-16"))
    (root / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")
    (root / "image.bin").write_bytes(b"\x89PNG\x00\x00\x01\x02" * 50)
    (root / "node_modules" / "dep.txt").write_text(SAMPLE, encoding="utf-8")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    if can_symlink():
        (root / "link.txt").symlink_to(outside)
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "pipe")
    return root


@functools.cache
def can_symlink() -> bool:
    """Windows needs Developer Mode or admin rights to create symlinks."""
    if sys.platform != "win32":
        return True
    probe = Path(tempfile.mkdtemp()) / "probe"
    try:
        probe.symlink_to(probe.parent)
        return True
    except OSError:
        return False


requires_symlinks = pytest.mark.skipif(not can_symlink(), reason="symlinks need Developer Mode or admin on Windows")


def assert_private(path: Path, mode: int) -> None:
    """Owner-only: the POSIX mode bits, or on Windows a protected ACL for the user and SYSTEM only."""
    if sys.platform != "win32":
        assert oct(path.stat().st_mode & 0o777) == oct(mode), path
        return
    from pii_scan.winapi import dacl_sddl, private_sddl

    expected_sddl = canonical_sddl(private_sddl(directory=path.is_dir()))
    actual, expected = _parse_dacl(dacl_sddl(str(path))), _parse_dacl(expected_sddl)
    assert "P" in actual[0], (path, actual)  # protected: nothing inherited from the parent
    assert actual[1] == expected[1], (path, actual)


def canonical_sddl(sddl: str) -> str:
    """`sddl` as Windows writes it back (a SID may come back as an alias such as LA)."""
    import ctypes
    from ctypes import wintypes

    from pii_scan import winapi

    descriptor = ctypes.c_void_p()
    assert winapi._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None)
    try:
        text = wintypes.LPWSTR()
        assert winapi._advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 0x4, ctypes.byref(text), None)
        try:
            return text.value
        finally:
            winapi._kernel32.LocalFree(text)
    finally:
        winapi._kernel32.LocalFree(descriptor)


def _parse_dacl(sddl: str) -> tuple[str, frozenset[str]]:
    """("PAI", {"A;;FA;;;S-1-5-...", ...}): Windows may add flags such as AI when reading an ACL back."""
    m = re.fullmatch(r"D:([A-Z]*)((?:\([^)]*\))*)", sddl)
    assert m, sddl
    return m.group(1), frozenset(re.findall(r"\(([^)]*)\)", m.group(2)))


def git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout
