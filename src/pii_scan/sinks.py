"""Machine-readable outputs. Each sink streams results; only json and sarif buffer (findings only)."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import IO, TYPE_CHECKING

from . import __version__
from .models import FileResult, Finding, Severity, Status
from .state import finding_to_dict, json_safe, report_path

if TYPE_CHECKING:
    from .pipeline import Summary

SARIF_MAX_RESULTS = 25_000
GITHUB_MAX_ANNOTATIONS = 50


def clean(text: str) -> str:
    """Escape control and format characters so paths and previews can't inject terminal or CI commands."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}"
                   for c in text)  # fmt: skip


def display_path(r: FileResult) -> str:
    return clean(r.relpath or r.path)


def _finding_record(r: FileResult, f: Finding, *, suppressed: bool = False) -> dict:
    rec = {"kind": "finding", "schema": 1, "relpath": json_safe(r.relpath), **finding_to_dict(f)}
    rec["path"] = json_safe(f.path)
    if suppressed:
        rec["suppressed"] = True
    return rec


class MultiSink:
    def __init__(self, sinks: list) -> None:
        self.sinks = sinks

    def file(self, result: FileResult) -> None:
        for s in self.sinks:
            s.file(result)

    def close(self, summary: Summary) -> None:
        for s in self.sinks:
            s.close(summary)


class TextSink:
    """One line per finding: path:line:col: SEVERITY TYPE (detector score): preview."""

    def __init__(self, stream: IO[str]) -> None:
        self.stream = stream

    def file(self, r: FileResult) -> None:
        path = display_path(r)
        for f in r.findings:
            self.stream.write(
                f"{path}:{f.line}:{f.column}: {str(f.severity).upper()} {clean(f.type)} "
                f"({clean(f.detector)} {f.score:.2f}): {clean(f.preview)}\n"
            )

    def close(self, summary: Summary) -> None:
        self.stream.flush()


class JsonlSink:
    """Canonical stream: one `file` record per analyzed file, `finding` records, then `summary`.

    Findings suppressed by a baseline are included with `"suppressed": true`, so masking from the
    report still removes them.
    """

    def __init__(self, stream: IO[str]) -> None:
        self.stream = stream

    def _write(self, obj: dict) -> None:
        self.stream.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")

    def file(self, r: FileResult) -> None:
        if r.status is Status.EXCLUDED:
            return
        self._write({
            "kind": "file", "schema": 1, "path": json_safe(r.path), "relpath": json_safe(r.relpath),
            "status": r.status.value, "reason": json_safe(r.reason), "size": r.size, "encoding": r.encoding,
            "sha256": r.sha256, "findings": len(r.findings), "suppressed": r.suppressed,
            "masked_path": json_safe(r.masked_path),
        })  # fmt: skip
        for f in r.findings:
            self._write(_finding_record(r, f))
        for f in r.suppressed_findings:
            self._write(_finding_record(r, f, suppressed=True))

    def close(self, summary: Summary) -> None:
        self._write({"kind": "summary", "schema": 1, "version": __version__, **summary.to_dict()})
        self.stream.flush()


class JsonSink:
    """Single JSON document (buffers files with findings or errors). Prefer jsonl for large scans."""

    def __init__(self, stream: IO[str]) -> None:
        self.stream = stream
        self.files: list[dict] = []

    def file(self, r: FileResult) -> None:
        if r.status in (Status.FINDINGS, Status.NOT_SCANNED):
            self.files.append({
                "path": json_safe(r.path), "relpath": json_safe(r.relpath), "status": r.status.value,
                "reason": json_safe(r.reason), "findings": [_finding_record(r, f) for f in r.findings],
            })  # fmt: skip

    def close(self, summary: Summary) -> None:
        json.dump({"version": __version__, "summary": summary.to_dict(), "files": self.files},
                  self.stream, indent=2, ensure_ascii=False)  # fmt: skip
        self.stream.write("\n")
        self.stream.flush()


class CsvSink:
    HEADER = ["path", "line", "column", "severity", "type", "detector", "score", "rule", "preview", "fingerprint"]

    def __init__(self, stream: IO[str]) -> None:
        self.writer = csv.writer(stream)
        self.writer.writerow(self.HEADER)
        self.stream = stream

    def file(self, r: FileResult) -> None:
        for f in r.findings:
            self.writer.writerow([_cell(json_safe(r.relpath or r.path)), f.line, f.column, str(f.severity),
                                  _cell(f.type), _cell(f.detector), f"{f.score:.2f}", _cell(f.rule),
                                  _cell(f.preview), f.fingerprint])  # fmt: skip

    def close(self, summary: Summary) -> None:
        self.stream.flush()


def _cell(value: str) -> str:
    """Neutralize spreadsheet formula injection."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


class SarifSink:
    """SARIF 2.1.0 for GitHub code scanning (results capped at the 25,000 upload limit).

    Locations are relative to the working directory (the workspace in CI). Partial fingerprints are
    emitted only when fingerprints are stable across runs (PII_SCAN_HMAC_KEY is set).
    """

    LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
    SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0"}

    def __init__(self, stream: IO[str], *, stable_fingerprints: bool = False) -> None:
        self.stream = stream
        self.stable = stable_fingerprints
        self.results: list[dict] = []
        self.rules: dict[str, dict] = {}
        self.dropped = 0

    def file(self, r: FileResult) -> None:
        for f in r.findings:
            if len(self.results) >= SARIF_MAX_RESULTS:
                self.dropped += 1
                continue
            rule_id = f"pii-scan/{f.type}"
            self.rules.setdefault(rule_id, {
                "id": rule_id, "name": f.type,
                "shortDescription": {"text": f"Sensitive data: {f.type}"},
                "properties": {"security-severity": self.SECURITY_SEVERITY[f.severity], "tags": ["security", "pii"]},
            })  # fmt: skip
            result = {
                "ruleId": rule_id,
                "level": self.LEVEL[f.severity],
                "message": {"text": f"{f.type} detected by {f.detector} ({f.score:.2f}): {f.preview}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": report_path(f.path)},
                    "region": {"startLine": f.line, "startColumn": f.column,
                               "endLine": f.end_line, "endColumn": f.end_column},
                }}],
            }  # fmt: skip
            if self.stable:
                result["partialFingerprints"] = {"piiScan/v1": f.fingerprint}
            self.results.append(result)

    def close(self, summary: Summary) -> None:
        if self.dropped:
            summary.report_truncated = True  # GithubSink, closed after this sink, reports it
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "pii-scan", "version": __version__,
                                    "informationUri": "https://github.com/ventz/pii-scan",
                                    "rules": list(self.rules.values())}},
                "results": self.results,
                "properties": {"summary": summary.to_dict(), "droppedResults": self.dropped},
            }],
        }  # fmt: skip
        json.dump(doc, self.stream, indent=2, ensure_ascii=False)
        self.stream.write("\n")
        self.stream.flush()


class GithubSink:
    """Workflow-command annotations (capped) and a Markdown job summary."""

    def __init__(self, stream: IO[str], fail_on: Severity | None) -> None:
        self.stream = stream
        self.fail_on = fail_on
        self.count = 0
        self.hidden = 0

    def file(self, r: FileResult) -> None:
        for f in r.findings:
            if self.count >= GITHUB_MAX_ANNOTATIONS:
                self.hidden += 1
                continue
            self.count += 1
            blocking = self.fail_on is not None and f.severity >= self.fail_on
            kind = "error" if blocking else "warning"
            props = (f"file={_prop(report_path(f.path))},line={f.line},col={f.column},"
                     f"endColumn={f.end_column},title={_prop(f'{str(f.severity).upper()} {f.type}')}")  # fmt: skip
            self.stream.write(f"::{kind} {props}::{_data(f'{f.type} detected by {f.detector}: {f.preview}')}\n")

    def close(self, summary: Summary) -> None:
        self._write_summary(summary)
        output = os.environ.get("GITHUB_OUTPUT")
        if output:
            # Step output for workflows, written last: exit code 1 (findings) doesn't say whether
            # every file was scanned, and a partial SARIF upload could close code-scanning alerts
            # that still exist. A report cut off at its result cap is partial too.
            complete = not (summary.incomplete or summary.report_truncated)
            with Path(output).open("a", encoding="utf-8") as fh:
                fh.write(f"complete={'true' if complete else 'false'}\n")

    def _write_summary(self, summary: Summary) -> None:
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not path:
            return
        lines = ["## PII scan", "", verdict(summary), ""]
        lines += ["| Result | Count |", "| --- | --- |"]
        for label, key in (("Files with findings", "findings"), ("Clean files", "clean"),
                           ("Files not scanned", "not_scanned"), ("Files skipped", "excluded")):  # fmt: skip
            lines.append(f"| {label} | {summary.status.get(key, 0):,} |")
        for sev in ("critical", "high", "medium", "low"):
            if summary.by_severity.get(sev):
                lines.append(f"| {sev.capitalize()} findings | {summary.by_severity[sev]:,} |")
        if self.hidden:
            lines += ["", f"{self.hidden:,} more findings are not annotated; see the uploaded report."]
        if summary.report_truncated:
            lines += ["", "The report was cut off at its result limit, so it is incomplete."]
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def _prop(value: str) -> str:
    return _data(value).replace(":", "%3A").replace(",", "%2C")


def _data(value: str) -> str:
    return clean(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def verdict(summary: Summary) -> str:
    if summary.interrupted:
        return "INTERRUPTED: the scan was stopped before it finished."
    if summary.aborted:
        return f"ERROR: the scan stopped: {clean(summary.aborted)}"
    ns = summary.status.get("not_scanned", 0)
    if summary.blocking:
        fail_on = str(summary.fail_on) if summary.fail_on else "never"
        extra = f" {ns:,} files could not be scanned." if ns else ""
        return f"FAILED: {summary.blocking:,} findings at or above {fail_on} severity.{extra}"
    if ns:
        return f"INCOMPLETE: {ns:,} files could not be scanned; no blocking findings in the rest."
    return "PASSED: no findings at or above the failure threshold."
