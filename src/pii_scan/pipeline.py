"""Scan pipeline: source -> bounded queue -> file workers -> bounded queue -> single writer.

- Nothing is held in memory per run except counters (and the baseline keys when writing one).
- Every file ends as CLEAN, FINDINGS, NOT_SCANNED(reason) or EXCLUDED(reason).
- The worker function is pure with respect to shared state, so it can move to processes later.
"""

from __future__ import annotations

import hashlib
import queue
import re
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Protocol

from .chunking import LineIndex
from .detectors.aws import AwsSession
from .detectors.base import DetectorError
from .detectors.regex import RegexDetector
from .layers import Layer, detect_remote
from .masking import Masker, preview, safe_output_path, verify_masked, write_atomic
from .models import FileResult, Finding, Severity, Span, Status
from .settings import Settings
from .sniff import SNIFF_BYTES, decode, detect_encoding, encode_like
from .sources.base import FileRef, ReadError, Source
from .spans import dedupe, merge
from .state import Baseline, ResultCache

_DONE = object()
_MAX_CONSECUTIVE_REMOTE_ERRORS = 25
_UNDECODABLE_RATIO = 0.01
_SURROGATE = re.compile("[\udc80-\udcff]")
_ESCAPABLE_ENCODINGS = ("utf-8", "cp1252")


class Sink(Protocol):
    def file(self, result: FileResult) -> None: ...
    def close(self, summary: Summary) -> None: ...


@dataclass
class Summary:
    started: float = field(default_factory=time.monotonic)
    elapsed: float = 0.0
    status: Counter[str] = field(default_factory=Counter)
    not_scanned: Counter[str] = field(default_factory=Counter)
    excluded: Counter[str] = field(default_factory=Counter)
    by_severity: Counter[str] = field(default_factory=Counter)
    by_type: Counter[str] = field(default_factory=Counter)
    blocking: int = 0
    suppressed: int = 0
    bytes_scanned: int = 0
    cached: int = 0
    masked: int = 0
    aborted: str = ""
    interrupted: bool = False
    report_truncated: bool = False  # set by a sink that had to drop results (SARIF's 25,000 cap)
    fail_on: Severity | None = None
    aws_usage: dict[str, Any] = field(default_factory=dict)
    not_scanned_examples: list[tuple[str, str]] = field(default_factory=list)

    @property
    def files_total(self) -> int:
        return sum(self.status.values())

    @property
    def incomplete(self) -> bool:
        return bool(self.status.get(Status.NOT_SCANNED.value) or self.aborted or self.interrupted)

    def exit_code(self, allow_incomplete: bool) -> int:
        if self.interrupted:
            return 130
        if self.aborted:
            return 2
        if self.blocking:
            return 1
        if self.incomplete and not allow_incomplete:
            return 3
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": dict(self.status),
            "not_scanned_reasons": dict(self.not_scanned),
            "excluded_reasons": dict(self.excluded),
            "findings_by_severity": dict(self.by_severity),
            "findings_by_type": dict(self.by_type),
            "blocking_findings": self.blocking,
            "baseline_suppressed": self.suppressed,
            "bytes_scanned": self.bytes_scanned,
            "cached_files": self.cached,
            "masked_files": self.masked,
            "fail_on": str(self.fail_on) if self.fail_on else "never",
            "aborted": self.aborted,
            "interrupted": self.interrupted,
            "elapsed_seconds": round(self.elapsed, 3),
            "aws": self.aws_usage,
        }


class Scanner:
    def __init__(
        self,
        settings: Settings,
        source: Source,
        regex: RegexDetector,
        layers: list[Layer],
        masker: Masker,
        sink: Sink,
        *,
        aws: AwsSession | None = None,
        cache: ResultCache | None = None,
        baseline: Baseline | None = None,
        stop: threading.Event | None = None,
        on_tick: Callable[[Summary, bool], None] | None = None,
        api_threads: int = 16,
    ) -> None:
        self.s = settings
        self.source = source
        self.regex = regex
        self.layers = layers
        self.masker = masker
        self.sink = sink
        self.aws = aws
        self.cache = cache
        self.baseline = baseline
        self.stop = stop or threading.Event()
        self.on_tick = on_tick
        self.api_threads = api_threads
        self.baseline_keys: set[str] = set()
        self._validators = {t: re.compile(p) for t, p in settings.validation_patterns.items()}
        self._err_lock = threading.Lock()
        self._consecutive_remote_errors = 0
        self._fatal = ""
        self._enumerated = 0

    # --- orchestration -----------------------------------------------------------------------

    def run(self) -> Summary:
        summary = Summary(fail_on=self.s.fail_on)
        workers = self.s.workers
        work_q: queue.Queue[Any] = queue.Queue(maxsize=workers * 4)
        result_q: queue.Queue[Any] = queue.Queue(maxsize=workers * 4)
        api_pool = ThreadPoolExecutor(self.api_threads, thread_name_prefix="pii-api") if self.layers else None

        def feeder() -> None:
            try:
                for ref in self.source:
                    if self.stop.is_set():
                        break
                    self._enumerated += 1  # only this thread writes it
                    direct = self._triage(ref)
                    if direct is not None:
                        self._put(result_q, direct)
                    else:
                        self._put(work_q, ref)
            except Exception as exc:  # noqa: BLE001 - enumeration failure aborts the run
                self._abort(f"file enumeration failed: {exc}")
            finally:
                for _ in range(workers):
                    work_q.put(_DONE)

        def worker() -> None:
            try:
                while True:
                    ref = work_q.get()
                    if ref is _DONE:
                        return
                    if self.stop.is_set():
                        continue  # drain
                    self._put(result_q, self._process_safe(ref, api_pool))
            finally:
                result_q.put(_DONE)

        threads = [threading.Thread(target=feeder, name="pii-feeder", daemon=True)]
        threads += [threading.Thread(target=worker, name=f"pii-worker-{i}", daemon=True) for i in range(workers)]
        for t in threads:
            t.start()

        done = 0
        last_tick = 0.0
        try:
            while done < workers:
                try:
                    item = result_q.get(timeout=0.5)
                except queue.Empty:
                    item = None
                if item is _DONE:
                    done += 1
                elif item is not None:
                    self._record(item, summary)
                now = time.monotonic()
                if self.on_tick and now - last_tick >= 0.5:
                    last_tick = now
                    summary.elapsed = now - summary.started
                    self.on_tick(summary, False)
        except KeyboardInterrupt:
            summary.interrupted = True
            self.stop.set()
            # keep draining so workers can exit
            while done < workers:
                try:
                    item = result_q.get(timeout=5)
                except queue.Empty:
                    break
                if item is _DONE:
                    done += 1
                else:
                    self._record(item, summary)
        finally:
            if api_pool is not None:
                api_pool.shutdown(wait=False, cancel_futures=True)

        summary.aborted = self._fatal
        if not summary.aborted and not summary.interrupted and summary.files_total != self._enumerated:
            missing = self._enumerated - summary.files_total
            summary.aborted = f"internal error: {missing} enumerated files have no recorded result"
        summary.elapsed = time.monotonic() - summary.started
        if self.aws is not None:
            summary.aws_usage = {
                "account_region": self.aws.region,
                "calls": dict(self.aws.usage.calls),
                "units": dict(self.aws.usage.units),
                "characters_sent": self.aws.usage.chars,
                "estimated_cost_usd": round(self.aws.usage.estimated_cost(), 4),
            }
        if self.cache is not None:
            self.cache.close()
        if self.on_tick:
            self.on_tick(summary, True)
        self.sink.close(summary)
        return summary

    def _put(self, q: queue.Queue[Any], item: Any) -> None:
        while True:
            try:
                q.put(item, timeout=0.5)
                return
            except queue.Full:
                if self.stop.is_set() and q.maxsize and item is not _DONE:
                    return

    def _abort(self, message: str) -> None:
        with self._err_lock:
            if not self._fatal:
                self._fatal = message
        self.stop.set()

    def _triage(self, ref: FileRef) -> FileResult | None:
        if ref.excluded:
            return FileResult(ref.path, Status.EXCLUDED, ref.excluded, size=max(ref.size, 0), relpath=ref.relpath)
        if ref.error:
            return FileResult(ref.path, Status.NOT_SCANNED, ref.error.split(":", 1)[0], size=max(ref.size, 0),
                              relpath=ref.relpath)  # fmt: skip
        if self.cache is not None and self.s.mask_out is None and ref.size >= 0:
            hit = self.cache.get(ref.source, ref.path, ref.size, ref.mtime_ns, ref.etag)
            if hit is not None:
                hit.relpath = ref.relpath
                return self._apply_baseline(hit)
        return None

    def _record(self, r: FileResult, summary: Summary) -> None:
        summary.status[r.status.value] += 1
        if r.status is Status.NOT_SCANNED:
            summary.not_scanned[r.reason] += 1
            if len(summary.not_scanned_examples) < 20:
                summary.not_scanned_examples.append((r.path, r.reason))
        elif r.status is Status.EXCLUDED:
            summary.excluded[r.reason] += 1
        else:
            summary.bytes_scanned += r.size
        if r.cached:
            summary.cached += 1
        if r.masked_path:
            summary.masked += 1
        summary.suppressed += r.suppressed
        for f in r.findings:
            summary.by_severity[str(f.severity)] += 1
            summary.by_type[f.type] += 1
            if self.s.fail_on is not None and f.severity >= self.s.fail_on:
                summary.blocking += 1
        if self.s.write_baseline is not None:
            for f in (*r.findings, *r.suppressed_findings):
                self.baseline_keys.add(Baseline.key(f))
        if self.cache is not None and not r.cached and self.s.mask_out is None:
            self.cache.put(getattr(self.source, "name", "fs"), r, r.mtime_ns)
        self.sink.file(r)

    # --- per file ----------------------------------------------------------------------------

    def _process_safe(self, ref: FileRef, api_pool: ThreadPoolExecutor | None) -> FileResult:
        """Every file gets a result: an unexpected error anywhere marks it not scanned."""
        try:
            return self._process(ref, api_pool)
        except Exception as exc:  # noqa: BLE001
            return FileResult(ref.path, Status.NOT_SCANNED, f"internal_error: {type(exc).__name__}",
                              size=max(ref.size, 0), relpath=ref.relpath)  # fmt: skip

    def _process(self, ref: FileRef, api_pool: ThreadPoolExecutor | None) -> FileResult:
        result = FileResult(ref.path, Status.NOT_SCANNED, size=max(ref.size, 0), relpath=ref.relpath,
                            mtime_ns=ref.mtime_ns)  # fmt: skip
        try:
            data = self.source.read(ref, self.s.max_file_size)
        except ReadError as exc:
            result.reason = exc.reason
            return result

        result.size = len(data)
        result.sha256 = hashlib.sha256(data).hexdigest()
        encoding = detect_encoding(data[:SNIFF_BYTES], truncated=len(data) > SNIFF_BYTES)
        if encoding is None:
            if self.s.binary_policy == "fail":
                result.reason = "binary"
            else:
                result.status, result.reason = Status.EXCLUDED, "binary"
            return result
        result.encoding = encoding
        text = decode(data, encoding)
        if (text and encoding in _ESCAPABLE_ENCODINGS and not text.isascii()
                and sum(1 for _ in _SURROGATE.finditer(text)) / len(text) > _UNDECODABLE_RATIO):  # fmt: skip
            result.reason = "undecodable"
            return result

        try:
            spans = self.regex.detect(text)
        except DetectorError as exc:  # e.g. match_limit: never report or mask a partial result
            result.reason = _reason(str(exc))
            return result
        try:
            if self.layers and text.strip():
                remote = detect_remote(text, self.layers, api_pool)
                self._remote_ok()
                spans.extend(self._validate(text, remote))
        except DetectorError as exc:
            if exc.fatal:
                self._abort(str(exc))
            else:
                self._remote_failed(str(exc))
            result.reason = _reason(str(exc))
            return result

        spans = dedupe(spans)
        result.findings = self._findings(ref, text, spans)
        result.status = Status.FINDINGS if result.findings else Status.CLEAN
        if self.s.mask_out is not None:
            try:
                self._write_masked(result, ref, data, text, encoding, spans)
            except Exception as exc:  # noqa: BLE001 - a failed masked write must be visible
                result.status, result.reason = Status.NOT_SCANNED, f"mask_failed: {type(exc).__name__}"
                result.findings = []
                return result
        return self._apply_baseline(result)

    def _validate(self, text: str, spans: Iterable[Span]) -> list[Span]:
        if not self._validators:
            return list(spans)
        out = []
        for s in spans:
            v = self._validators.get(s.type)
            if v is None or v.fullmatch(text[s.start:s.end]):
                out.append(s)
        return out

    def _findings(self, ref: FileRef, text: str, spans: list[Span]) -> list[Finding]:
        if not spans:
            return []
        idx = LineIndex(text)
        out: list[Finding] = []
        for s in spans:
            value = text[s.start:s.end]
            line, col = idx.position(s.start)
            end_line, end_col = idx.position(max(s.start, s.end - 1))
            out.append(Finding(
                path=ref.path, line=line, column=col, end_line=end_line, end_column=end_col + 1,
                start=s.start, end=s.end, type=s.type, severity=self.s.severity_of(s.type),
                score=s.score, detector=s.detector, rule=s.rule,
                preview=preview(value, s.type, reveal=self.s.show_values),
                fingerprint=self.masker.fingerprint(value),
            ))  # fmt: skip
        return out

    def _apply_baseline(self, r: FileResult) -> FileResult:
        if self.baseline is None or not r.findings:
            return r
        kept, suppressed = [], []
        for f in r.findings:
            (suppressed if Baseline.key(f) in self.baseline else kept).append(f)
        r.findings, r.suppressed_findings, r.suppressed = kept, suppressed, len(suppressed)
        if r.status is Status.FINDINGS and not kept:
            r.status = Status.CLEAN
        return r

    def _write_masked(self, r: FileResult, ref: FileRef, data: bytes, text: str, encoding: str,
                      spans: list[Span]) -> None:  # fmt: skip
        assert self.s.mask_out is not None
        if not spans and self.s.mask_findings_only:
            return
        dest = safe_output_path(self.s.mask_out, ref.relpath)
        if not spans:
            write_atomic(dest, data)
        else:
            regions = merge(spans, self.s.severity_of)
            masked = self.masker.apply(text, regions)
            verify_masked(text, spans, masked)
            write_atomic(dest, encode_like(masked, encoding))
        r.masked_path = str(dest)

    def _remote_ok(self) -> None:
        with self._err_lock:
            self._consecutive_remote_errors = 0

    def _remote_failed(self, message: str) -> None:
        with self._err_lock:
            self._consecutive_remote_errors += 1
            count = self._consecutive_remote_errors
        if count >= _MAX_CONSECUTIVE_REMOTE_ERRORS:
            self._abort(f"{count} consecutive AWS failures, last: {message}")


def _reason(message: str) -> str:
    """Short, stable reason code for summaries (full messages stay in verbose logs)."""
    head = message.split(":", 2)
    if len(head) >= 3:
        return f"{head[0]}:{head[1]}:{head[2].split(':', 1)[0].strip()}"[:120]
    return message[:120]
