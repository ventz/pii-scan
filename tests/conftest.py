import os
import subprocess
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
    for var in ("CI", "GITHUB_ACTIONS", "GITHUB_BASE_REF", "PII_SCAN_HMAC_KEY", "GITHUB_STEP_SUMMARY"):
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
    (root / "link.txt").symlink_to(outside)
    if hasattr(os, "mkfifo"):
        os.mkfifo(root / "pipe")
    return root


def git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout
