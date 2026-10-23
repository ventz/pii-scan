"""Persistent state: the resume cache (SQLite) and the findings baseline."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

from .models import FileResult, Finding, Severity, Status
from .private import create_private_file, make_private, make_private_dirs

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    source TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    etag TEXT NOT NULL DEFAULT '',
    config_hash TEXT NOT NULL,
    result TEXT NOT NULL,
    PRIMARY KEY (source, path)
);
"""


def json_safe(text: str) -> str:
    """Escape lone surrogates (undecodable bytes in file names) so the text encodes as UTF-8."""
    if text.isascii():
        return text
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def report_path(path: str) -> str:
    """Path relative to the working directory with '/' separators.

    Used for baselines, SARIF, and GitHub annotations so they agree between `--all` and
    changed-files mode, and point at workspace files in CI.
    """
    try:
        rel = os.path.relpath(path)
    except ValueError:  # a different drive on Windows
        rel = path
    return json_safe(rel.replace(os.sep, "/"))


class ResultCache:
    """Skip files unchanged since a previous run with the same configuration.

    Stores statuses and masked findings (before any baseline is applied), never raw text. Keep the
    database on local disk, not on the share being scanned. Only CLEAN and FINDINGS are cached.
    """

    def __init__(self, path: Path, config_hash: str) -> None:
        self.path = path
        self.config_hash = config_hash
        # The database is created owner-only before SQLite writes anything. SQLite creates -wal and
        # -shm itself: on Windows they inherit the folder's ACL (private only if pii-scan created
        # the folder) until make_private below, when they hold no more than the schema.
        make_private_dirs(path.parent)
        if not path.exists():
            os.close(create_private_file(path, 0o600))
        self._local = threading.local()
        conn = self._conn()
        conn.executescript(_SCHEMA)
        conn.commit()
        for suffix in ("", "-wal", "-shm"):  # results reveal where sensitive data lives: owner-only
            p = Path(f"{path}{suffix}")
            if p.exists():
                make_private(p, 0o600)
        self._pending = 0

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def get(self, source: str, path: str, size: int, mtime_ns: int, etag: str = "") -> FileResult | None:
        row = self._conn().execute(
            "SELECT result FROM files WHERE source=? AND path=? AND size=? AND mtime_ns=? AND etag=? "
            "AND config_hash=?",
            (source, json_safe(path), size, mtime_ns, etag, self.config_hash),
        ).fetchone()
        return _result_from_json(row[0]) if row else None

    def put(self, source: str, result: FileResult, mtime_ns: int, etag: str = "") -> None:
        if result.status not in (Status.CLEAN, Status.FINDINGS):
            return
        everything = result.findings + result.suppressed_findings
        stored = replace(result, findings=everything, suppressed_findings=[], suppressed=0,
                         status=Status.FINDINGS if everything else Status.CLEAN)  # fmt: skip
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO files(source, path, size, mtime_ns, etag, config_hash, result) "
            "VALUES (?,?,?,?,?,?,?)",
            (source, json_safe(result.path), result.size, mtime_ns, etag, self.config_hash, _result_to_json(stored)),
        )
        self._pending += 1
        if self._pending >= 500:
            conn.commit()
            self._pending = 0

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.commit()
            conn.close()
            self._local.conn = None


def _result_to_json(r: FileResult) -> str:
    return json.dumps(
        {
            "path": r.path, "status": r.status.value, "size": r.size, "encoding": r.encoding,
            "sha256": r.sha256,
            "findings": [finding_to_dict(f) for f in r.findings],
        },
        separators=(",", ":"),
    )  # fmt: skip


def _result_from_json(text: str) -> FileResult:
    d = json.loads(text)
    r = FileResult(d["path"], Status(d["status"]), size=d["size"], encoding=d["encoding"])
    r.sha256 = d.get("sha256", "")
    r.findings = [finding_from_dict(f) for f in d["findings"]]
    r.cached = True
    return r


def finding_to_dict(f: Finding) -> dict:
    return {
        "path": f.path, "line": f.line, "column": f.column, "end_line": f.end_line,
        "end_column": f.end_column, "start": f.start, "end": f.end, "type": f.type,
        "severity": str(f.severity), "score": round(f.score, 4), "detector": f.detector, "rule": f.rule,
        "preview": f.preview, "fingerprint": f.fingerprint,
    }  # fmt: skip


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        d["path"], d["line"], d["column"], d["end_line"], d["end_column"], d["start"], d["end"],
        d["type"], Severity.parse(d["severity"]), d["score"], d["detector"], d["rule"], d["preview"],
        d["fingerprint"],
    )  # fmt: skip


class Baseline:
    """Accepted findings, keyed by working-directory-relative path, type, and keyed fingerprint.

    Requires a stable PII_SCAN_HMAC_KEY so fingerprints match between runs.
    """

    def __init__(self, fingerprints: set[str]) -> None:
        self.fingerprints = fingerprints

    @classmethod
    def load(cls, path: Path) -> Baseline:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read baseline {path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), list):
            raise ValueError(f"{path}: expected {{\"version\": 1, \"fingerprints\": [...]}}")
        return cls({str(x) for x in data["fingerprints"]})

    @staticmethod
    def key(f: Finding) -> str:
        return f"{report_path(f.path)}|{f.type}|{f.fingerprint}"

    def __contains__(self, key: str) -> bool:
        return key in self.fingerprints

    @staticmethod
    def write(path: Path, keys: set[str]) -> None:
        from .masking import write_atomic

        data = json.dumps({"version": 1, "fingerprints": sorted(keys)}, indent=2) + "\n"
        write_atomic(path, data.encode("utf-8"))
