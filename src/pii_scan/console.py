"""Human-facing output on stderr: progress, warnings, and the final summary (plain ASCII)."""

from __future__ import annotations

import os
import sys
import time
from typing import IO, TYPE_CHECKING

from .sinks import clean, verdict

if TYPE_CHECKING:
    from .pipeline import Summary


class Console:
    def __init__(self, *, quiet: bool = False, verbose: bool = False, progress: str = "auto",
                 stream: IO[str] | None = None, interval: float = 30.0) -> None:  # fmt: skip
        self.stream = stream or sys.stderr
        self.quiet = quiet
        self.verbose = verbose
        self.interval = interval
        tty = self.stream.isatty() and os.environ.get("TERM") != "dumb" and not os.environ.get("CI")
        if progress == "auto":
            progress = "bar" if tty else "lines"
        self.progress = "none" if quiet else progress
        self._last_line = time.monotonic()  # first progress line after one interval
        self._bar_active = False

    def info(self, message: str) -> None:
        if not self.quiet:
            self._clear_bar()
            self.stream.write(f"{message}\n")

    def debug(self, message: str) -> None:
        if self.verbose and not self.quiet:
            self._clear_bar()
            self.stream.write(f"debug: {message}\n")

    def warn(self, message: str) -> None:
        self._clear_bar()
        self.stream.write(f"warning: {clean(message)}\n")

    def error(self, message: str) -> None:  # never suppressed by --quiet
        self._clear_bar()
        self.stream.write(f"error: {clean(message)}\n")

    def tick(self, s: Summary, final: bool) -> None:
        if self.progress == "none":
            return
        files = s.files_total
        rate = files / s.elapsed if s.elapsed > 0 else 0.0
        text = (f"Progress: {files:,} files ({s.status.get('findings', 0):,} with findings, "
                f"{s.status.get('not_scanned', 0):,} not scanned), {rate:,.0f} files/s")  # fmt: skip
        if self.progress == "bar":
            if final:
                self._clear_bar()
            else:
                self.stream.write("\r" + text[:200].ljust(80))
                self.stream.flush()
                self._bar_active = True
            return
        now = time.monotonic()
        if not final and now - self._last_line >= self.interval:
            self._last_line = now
            self.stream.write(text + "\n")
            self.stream.flush()

    def _clear_bar(self) -> None:
        if self._bar_active:
            self.stream.write("\r" + " " * 80 + "\r")
            self._bar_active = False

    def summary(self, s: Summary, *, mask_out: str | None = None) -> None:
        self._clear_bar()
        w = self.stream.write
        if self.quiet:
            if s.blocking or s.incomplete:
                w(verdict(s) + "\n")
            return
        st = s.status
        w("\n" + verdict(s) + "\n")
        w(f"Files: {st.get('clean', 0) + st.get('findings', 0):,} scanned ({s.cached:,} from cache), "
          f"{st.get('findings', 0):,} with findings, {st.get('not_scanned', 0):,} not scanned, "
          f"{st.get('excluded', 0):,} skipped.\n")  # fmt: skip
        if s.not_scanned:
            w("Not scanned: " + _counts(s.not_scanned) + "\n")
            for path, reason in s.not_scanned_examples[: (20 if self.verbose else 5)]:
                w(f"  {clean(path)}: {clean(reason)}\n")
        if s.excluded:
            w("Skipped: " + _counts(s.excluded) + "\n")
        if s.by_severity:
            order = ["critical", "high", "medium", "low"]
            parts = [f"{k} {s.by_severity[k]:,}" for k in order if s.by_severity.get(k)]
            w(f"Findings: {', '.join(parts)}.")
            if s.suppressed:
                w(f" Baseline suppressed {s.suppressed:,}.")
            w("\n")
            w("By type: " + _counts(s.by_type, limit=12) + "\n")
        if s.aws_usage:
            calls = ", ".join(f"{k} {v:,}" for k, v in s.aws_usage["calls"].items() if v)
            w(f"AWS ({s.aws_usage['account_region']}): calls {calls or 'none'}; "
              f"estimated cost ${s.aws_usage['estimated_cost_usd']:,.2f} at list price.\n")  # fmt: skip
        if mask_out:
            w(f"Masked copies: {s.masked:,} files written under {clean(mask_out)}.\n")
        rate = s.files_total / s.elapsed if s.elapsed > 0 else 0.0
        w(f"Elapsed: {s.elapsed:,.1f}s ({rate:,.0f} files/s).\n")
        self.stream.flush()


def _counts(counter: dict[str, int], limit: int = 8) -> str:
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    text = ", ".join(f"{clean(k)} {v:,}" for k, v in items[:limit])
    if len(items) > limit:
        text += f", and {len(items) - limit} more"
    return text
