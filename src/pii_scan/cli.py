"""Command-line interface.

Exit codes: 0 passed, 1 findings at or above --fail-on, 2 usage/configuration/credential error,
3 incomplete (some files could not be scanned), 130 interrupted.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import stat
import sys
import threading
from dataclasses import replace
from pathlib import Path

from . import __version__
from .console import Console
from .detectors.aws import AwsSession, ComprehendDetector, ContainsScreen, GuardrailsDetector
from .detectors.base import DetectorError
from .detectors.regex import BUILTIN_RULES, RegexDetector, Rule, load_custom_rules
from .masking import Masker, MaskStyle, safe_output_path, verify_masked, write_atomic
from .models import Span, Status
from .private import WINDOWS, make_private_fd
from .settings import ConfigError, Settings, load_config_file, parse_severity_or_never
from .sinks import CsvSink, GithubSink, JsonlSink, JsonSink, MultiSink, SarifSink, TextSink
from .sniff import ENCODINGS, decode, encode_like
from .sources.fs import Excludes, FilesystemSource
from .sources.git import GitChangedSource, GitError
from .spans import dedupe, merge
from .state import Baseline, ResultCache

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INCOMPLETE, EXIT_INTERRUPTED = 0, 1, 2, 3, 130
EXIT_BROKEN_PIPE = 141
COMMANDS = {"scan", "mask", "doctor", "version"}
AWS_PRESET = ("regex", "contains", "detect")

EPILOG = """\
commands:
  scan        scan files (the default; the word "scan" is optional)
  mask        write masked copies from a saved jsonl report
  doctor      check AWS credentials and each detection layer
  version     print the version
  Run "pii-scan mask --help" or "pii-scan doctor --help" for their options.

examples:
  # changed files on this branch, including uncommitted work (regex only)
  pii-scan

  # a whole directory or share (regex only, nothing leaves the machine)
  pii-scan --all /mnt/share

  # add AWS detection for names, addresses, and free-text PII
  pii-scan --all --aws --region us-east-1 /mnt/share

  # write masked copies
  pii-scan --all --mask-out /secure/masked /mnt/share

  # save a report for a large scan, then mask from it
  pii-scan --all --output jsonl --report findings.jsonl /mnt/share
  pii-scan mask --from findings.jsonl --out /secure/masked --style hash

exit codes:
  0    passed
  1    findings at or above --fail-on (default: high)
  2    usage, configuration, or credential error
  3    incomplete: some files could not be scanned
  130  interrupted

docs: https://github.com/ventz/pii-scan#readme
"""


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("what to scan")
    g.add_argument("paths", nargs="*", default=["."], help="files or directories (default: current directory)")
    g.add_argument("--all", action="store_true", help="scan everything under the paths (default: only git changes)")
    g.add_argument("--base", metavar="REF", help="git ref to diff against in changed-files mode")
    g.add_argument("--trust-repo", action="store_true",
                   help="allow changed-files mode in repositories whose own git config "
                        "(local or worktree) sets filters, includes, or diff commands")
    g.add_argument("--exclude-dirs", metavar="LIST",
                   help="comma-separated directory names to skip (added to defaults)")
    g.add_argument("--exclude-exts", metavar="LIST", help="comma-separated file suffixes to skip (added to defaults)")
    g.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="root-relative glob to skip (repeatable), e.g. 'archive/**'")
    g.add_argument("--max-file-size", type=int, metavar="BYTES", help="larger files are reported as not scanned")
    g.add_argument("--same-filesystem", action="store_true", help="do not cross into other mounts")
    g.add_argument("--binary", choices=["skip", "fail"], help="binary files: skip (default) or count as not scanned")

    g = p.add_argument_group("detection")
    g.add_argument("--aws", action="store_true",
                   help="use AWS detection (shorthand for --layers regex,contains,detect); off by default")
    g.add_argument("--layers", metavar="LIST",
                   help="comma-separated: regex,contains,guardrails,detect (default: regex)")
    g.add_argument("--config", metavar="FILE", help="JSON configuration file")
    g.add_argument("--custom-regex", metavar="FILE", help="JSON file with custom regex rules")
    g.add_argument("--restricted-config", action="store_true",
                   help="treat --config and --custom-regex as untrusted: they may only add rules "
                        "(RE2 syntax, under the working directory) or raise severities")
    g.add_argument("--min-confidence", type=float, metavar="SCORE",
                   help="minimum score for AWS detections (default 0.85)")
    g.add_argument("--screen-threshold", type=float, metavar="SCORE",
                   help="minimum ContainsPiiEntities score to escalate (default 0.5)")
    g.add_argument("--entity-types", metavar="LIST", help="comma-separated AWS entity types to report")
    g.add_argument("--region", metavar="REGION", help="AWS region for AWS layers")
    g.add_argument("--profile", metavar="NAME", help="AWS profile for AWS layers")
    g.add_argument("--language", metavar="CODE", help="language code sent to AWS (default en)")
    g.add_argument("--guardrail-id", metavar="ID", help="Bedrock guardrail ID or ARN (guardrails layer)")
    g.add_argument("--guardrail-version", metavar="VERSION", help="Bedrock guardrail version (default DRAFT)")
    g.add_argument("--max-tps-contains", type=float, metavar="N",
                   help="ContainsPiiEntities requests per second (default 20)")
    g.add_argument("--max-tps-detect", type=float, metavar="N",
                   help="DetectPiiEntities requests per second (default 40)")
    g.add_argument("--aws-max-chars", type=int, metavar="N",
                   help="stop the run once N characters have been sent to AWS (cost ceiling)")

    g = p.add_argument_group("policy")
    g.add_argument("--fail-on", metavar="LEVEL", help="critical|high|medium|low|any|never (default high)")
    g.add_argument("--allow-incomplete", action="store_true", help="exit 0 even if some files could not be scanned")
    g.add_argument("--baseline", metavar="FILE", help="JSON baseline of accepted findings (needs PII_SCAN_HMAC_KEY)")
    g.add_argument("--write-baseline", metavar="FILE", help="write all current findings to this baseline file")

    g = p.add_argument_group("output")
    g.add_argument("--output", choices=["text", "json", "jsonl", "csv", "sarif"], help="format (default text)")
    g.add_argument("--report", metavar="FILE", help="write the formatted output to this file instead of stdout")
    g.add_argument("--github", action="store_true", help="also emit GitHub annotations and a job summary")
    g.add_argument("--show-values", action="store_true", help="print raw matched values (refused when CI is set)")
    g.add_argument("--progress", choices=["auto", "lines", "none"], help="progress on stderr (default auto)")
    g.add_argument("-v", "--verbose", action="store_true", help="more detail on stderr")
    g.add_argument("-q", "--quiet", action="store_true", help="only findings and errors")

    g = p.add_argument_group("masking")
    g.add_argument("--mask-out", metavar="DIR", help="write masked copies of scanned files under this directory")
    g.add_argument("--mask-style", choices=[m.value for m in MaskStyle], help="replacement style (default label)")
    g.add_argument("--mask-findings-only", action="store_true", help="only write files that had findings")

    g = p.add_argument_group("performance")
    g.add_argument("--workers", type=int, metavar="N", help="file worker threads (default 16)")
    g.add_argument("--cache", metavar="FILE",
                   help="SQLite file to skip unchanged files on re-runs (keep it off the share)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-scan",
        description="Find and mask PII and secrets in files, repositories, and file shares.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan", help="scan files (default command)", epilog=EPILOG,
        prog="pii-scan", usage="pii-scan [scan] [options] [PATH ...]",
        description="Find and mask PII and secrets in files, repositories, and file shares.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )  # fmt: skip
    scan.add_argument("--version", action="version", version=f"pii-scan {__version__}")
    _add_scan_args(scan)

    mask = sub.add_parser("mask", help="write masked copies from a jsonl report")
    mask.add_argument("--from", dest="source", required=True, help="jsonl report produced by 'scan --output jsonl'")
    mask.add_argument("--out", required=True, help="output directory (must not contain the scanned files)")
    mask.add_argument("--style", choices=[m.value for m in MaskStyle], default="label")
    mask.add_argument("--findings-only", action="store_true", help="only write files that had findings")
    mask.add_argument("--custom-regex", metavar="FILE",
                      help="custom rules to re-check, in addition to the built-in rules")
    mask.add_argument("-q", "--quiet", action="store_true")

    doctor = sub.add_parser("doctor", help="check AWS credentials and each detection layer")
    doctor.add_argument("--layers", default="contains,detect")
    doctor.add_argument("--region")
    doctor.add_argument("--profile")
    doctor.add_argument("--guardrail-id")
    doctor.add_argument("--guardrail-version", default="DRAFT")
    doctor.add_argument("--language", default="en")

    sub.add_parser("version", help="print the version")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # "scan" is the default command, so top-level --help shows the scan options people actually need.
    if not argv or argv[0] not in COMMANDS:
        argv.insert(0, "scan")
    parser = build_parser()
    # File names can contain undecodable bytes; never crash while printing them.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(f"pii-scan {__version__}")
            return EXIT_OK
        if args.command == "mask":
            return cmd_mask(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        return cmd_scan(args)
    except ConfigError as exc:
        Console().error(str(exc))
        return EXIT_USAGE
    except KeyboardInterrupt:
        Console().error("interrupted")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # stdout was closed early (e.g. piped into head): exit quietly like other CLI tools
        with contextlib.suppress(OSError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_BROKEN_PIPE
    except Exception as exc:  # noqa: BLE001 - a crash must never exit 1, which means "findings"
        Console().error(f"internal error: {type(exc).__name__}: {exc}")
        return EXIT_USAGE


# --- scan ----------------------------------------------------------------------------------------


def settings_from_args(args: argparse.Namespace) -> Settings:
    s = Settings()
    if args.config:
        s = load_config_file(Path(args.config), s, restricted=args.restricted_config)
    aws = s.aws
    changes: dict = {"paths": tuple(args.paths or ["."]), "scan_all": args.all, "base": args.base,
                     "trust_repo": args.trust_repo, "restricted_config": args.restricted_config}  # fmt: skip

    def csv(value: str | None) -> list[str]:
        return [v.strip() for v in (value or "").split(",") if v.strip()]

    if args.aws and args.layers:
        raise ConfigError("use either --aws or --layers, not both")
    if args.aws:
        changes["layers"] = AWS_PRESET
    elif args.layers:
        changes["layers"] = tuple(csv(args.layers))
    if args.min_confidence is not None:
        changes["min_confidence"] = args.min_confidence
    if args.screen_threshold is not None:
        changes["screen_threshold"] = args.screen_threshold
    if args.entity_types:
        changes["entity_types"] = frozenset(csv(args.entity_types))
    if args.custom_regex:
        changes["custom_rules"] = Path(args.custom_regex)
    if args.exclude_dirs:
        changes["exclude_dirs"] = tuple(dict.fromkeys([*s.exclude_dirs, *csv(args.exclude_dirs)]))
    if args.exclude_exts:
        changes["exclude_extensions"] = tuple(dict.fromkeys([*s.exclude_extensions, *csv(args.exclude_exts)]))
    if args.exclude:
        changes["exclude_globs"] = tuple(dict.fromkeys([*s.exclude_globs, *args.exclude]))
    if args.max_file_size is not None:
        changes["max_file_size"] = args.max_file_size
    if args.same_filesystem:
        changes["same_filesystem"] = True
    if args.binary:
        changes["binary_policy"] = args.binary
    if args.fail_on:
        try:
            changes["fail_on"] = parse_severity_or_never(args.fail_on)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    if args.allow_incomplete:
        changes["allow_incomplete"] = True
    if args.baseline:
        changes["baseline"] = Path(args.baseline)
    if args.write_baseline:
        changes["write_baseline"] = Path(args.write_baseline)
    if args.output:
        changes["output"] = args.output
    if args.report:
        changes["report"] = Path(args.report)
    if args.github:
        changes["github"] = True
    if args.show_values:
        changes["show_values"] = True
    if args.progress:
        changes["progress"] = args.progress
    changes["verbose"] = args.verbose
    changes["quiet"] = args.quiet
    if args.mask_out:
        changes["mask_out"] = Path(args.mask_out)
    if args.mask_style:
        changes["mask_style"] = MaskStyle(args.mask_style)
    if args.mask_findings_only:
        changes["mask_findings_only"] = True
    if args.workers is not None:
        changes["workers"] = args.workers
    if args.cache:
        changes["cache"] = Path(args.cache)

    aws_changes = {k: v for k, v in {
        "region": args.region, "profile": args.profile, "language": args.language,
        "guardrail_id": args.guardrail_id, "guardrail_version": args.guardrail_version,
        "tps_contains": args.max_tps_contains, "tps_detect": args.max_tps_detect,
        "max_chars": args.aws_max_chars,
    }.items() if v is not None}  # fmt: skip
    if aws_changes:
        aws = replace(aws, **aws_changes)
    legacy = getattr(s, "_legacy_regex_patterns", None)
    s = replace(s, **changes, aws=aws)
    if legacy:
        object.__setattr__(s, "_legacy_regex_patterns", legacy)
    if "detect" in s.layers and s.aws.language not in ("en", "es"):
        raise ConfigError("the detect layer supports only --language en or es")
    return s.validate()


def _untrusted_rules_file(path: Path) -> None:
    """Under --restricted-config the rules file comes from the scanned tree: keep it there."""
    real = path.resolve()
    workspace = Path.cwd().resolve()
    if real != workspace and workspace not in real.parents:
        raise ConfigError(f"custom rules file {path} is outside the working directory, "
                          "which --restricted-config refuses")  # fmt: skip
    if not real.is_file():
        raise ConfigError(f"custom rules file {path} is not a regular file")


def build_rules(s: Settings) -> list[Rule]:
    rules = list(BUILTIN_RULES)
    if s.custom_rules:
        if s.restricted_config:
            _untrusted_rules_file(s.custom_rules)
        try:
            rules += load_custom_rules(s.custom_rules, require_re2=s.restricted_config)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    legacy = getattr(s, "_legacy_regex_patterns", None)
    if legacy:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(legacy, fh)
        try:
            rules += load_custom_rules(Path(fh.name), require_re2=s.restricted_config)
        except ValueError as exc:
            raise ConfigError(f"regex_patterns: {exc}") from exc
        finally:
            os.unlink(fh.name)
    return rules


def config_hash(s: Settings, rules: list[Rule], key: bytes | None) -> str:
    material = {
        # fingerprints depend on the HMAC key (without a key they are per-run and unused by baselines/SARIF)
        "key": hashlib.sha256(key).hexdigest() if key else "no-key",
        "version": __version__, "layers": s.layers, "entity_types": sorted(s.entity_types),
        "min_confidence": s.min_confidence, "screen_threshold": s.screen_threshold,
        "severity": sorted((k, int(v)) for k, v in s.severity.items()),
        "validation": sorted(s.validation_patterns.items()), "max_matches": s.max_matches_per_rule,
        "rules": [(r.id, r.type, r.pattern.pattern, r.group) for r in rules],
        "language": s.aws.language, "guardrail": [s.aws.guardrail_id, s.aws.guardrail_version],
        "binary": s.binary_policy, "max_file_size": s.max_file_size,
    }  # fmt: skip
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


MIN_HMAC_KEY_BYTES = 16


def hmac_key(required: bool) -> bytes | None:
    raw = os.environ.get("PII_SCAN_HMAC_KEY")
    if not raw:
        if required:
            raise ConfigError("baselines need a stable key: set PII_SCAN_HMAC_KEY (for example a repository secret)")
        return None
    key = raw.encode("utf-8")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise ConfigError(f"PII_SCAN_HMAC_KEY must be at least {MIN_HMAC_KEY_BYTES} bytes; use a long random secret")
    return key


def cmd_scan(args: argparse.Namespace) -> int:
    s = settings_from_args(args)
    console = Console(quiet=s.quiet, verbose=s.verbose, progress=s.progress)
    for w in s.warnings:
        console.warn(w)

    rules = build_rules(s)
    severity = dict(s.severity)
    for r in rules:
        if r.severity is None:
            continue
        current = severity.get(r.type, r.severity)
        if s.restricted_config and r.severity < current:
            raise ConfigError(
                f"custom rule {r.id!r} lowers the severity of {r.type}, which --restricted-config forbids"
            )
        severity[r.type] = r.severity
    s = replace(s, severity=severity)

    excludes = Excludes(s.exclude_dirs, s.exclude_extensions, s.exclude_globs, s.exclude_files)
    if s.scan_all:
        source = FilesystemSource(s.paths, excludes, max_file_size=s.max_file_size, same_filesystem=s.same_filesystem,
                                  precise_change_time=s.cache is not None)  # fmt: skip
        source.name = "fs"  # type: ignore[attr-defined]
    else:
        if len(s.paths) != 1:
            raise ConfigError("changed-files mode takes one path; use --all to scan several")
        try:
            source = GitChangedSource(Path(s.paths[0]), s.base, excludes, max_file_size=s.max_file_size,
                                      trust_repo=s.trust_repo, precise_change_time=s.cache is not None)  # fmt: skip
        except GitError as exc:
            raise ConfigError(f"{exc}. To scan a directory that is not a git checkout, add --all.") from exc
        source.name = "git"  # type: ignore[attr-defined]
        console.debug(f"diffing against {source.base}")

    stop = threading.Event()
    aws = None
    layers = []
    api_threads = 8
    if s.remote_layers:
        peak = max(s.aws.tps_detect if "detect" in s.remote_layers else 0,
                   s.aws.tps_contains if "contains" in s.remote_layers else 0, 4)  # fmt: skip
        api_threads = min(128, math.ceil(peak * 1.5) + 4)
        try:
            # connection pool at least as large as the API thread pool, so threads never wait on it
            aws = AwsSession(replace(s.aws, pool_size=max(s.aws.pool_size, api_threads + 8)), stop)
            ident = aws.identity()
        except DetectorError as exc:
            raise ConfigError(str(exc)) from exc
        console.info(f"AWS account {ident['account']} in {ident['region']}; layers: {', '.join(s.layers)}")
        for name in s.remote_layers:
            if name == "contains":
                layers.append(ContainsScreen(aws, s.entity_types, s.screen_threshold))
            elif name == "guardrails":
                layers.append(GuardrailsDetector(aws, s.entity_types))
            elif name == "detect":
                layers.append(ComprehendDetector(aws, s.entity_types, s.min_confidence))

    baseline = None
    key = hmac_key(required=bool(s.baseline or s.write_baseline))
    if s.baseline:
        try:
            baseline = Baseline.load(s.baseline)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    masker = Masker(s.mask_style, key)
    cache = None
    if s.cache and s.show_values:
        console.warn("--cache is ignored with --show-values so raw values are never stored")
    elif s.cache:
        cache = ResultCache(s.cache, config_hash(s, rules, key))

    out_stream = _open_report(s.report) if s.report else sys.stdout
    try:
        if s.output == "sarif":
            primary = SarifSink(out_stream, stable_fingerprints=key is not None)
        else:
            primary = {"text": TextSink, "json": JsonSink, "jsonl": JsonlSink, "csv": CsvSink}[s.output](out_stream)
        sinks = [primary]
        if s.github:
            gh_stream = sys.stdout if s.report or s.output == "text" else sys.stderr
            sinks.append(GithubSink(gh_stream, s.fail_on))
        from .pipeline import Scanner

        scanner = Scanner(
            s, source, RegexDetector(rules, max_matches_per_rule=s.max_matches_per_rule), layers, masker,
            MultiSink(sinks), aws=aws, cache=cache, baseline=baseline, stop=stop, on_tick=console.tick,
            api_threads=api_threads,
        )
        summary = scanner.run()
    finally:
        if s.report:
            out_stream.close()

    if summary.aborted:
        console.error(summary.aborted)  # Console escapes control characters
    if s.write_baseline:
        Baseline.write(s.write_baseline, scanner.baseline_keys)
        console.info(f"Wrote {len(scanner.baseline_keys):,} baseline entries to {s.write_baseline}")
    console.summary(summary, mask_out=str(s.mask_out) if s.mask_out else None)
    return summary.exit_code(s.allow_incomplete)


def _open_report(path: Path):  # noqa: ANN202 - text stream
    """Create or overwrite the report without following a link, with owner-only permissions.

    An existing file is made private first and only then emptied, so a report that can't be made
    private is left as it was.
    """
    try:
        if WINDOWS:
            from .winapi import open_for_writing

            fd = open_for_writing(str(path))
        else:
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ConfigError(f"cannot write report {path}: {exc.strerror or exc} (symlinks are refused)") from exc
    try:
        make_private_fd(fd, 0o600)  # the open file itself, before anything is written
        if stat.S_ISREG(os.fstat(fd).st_mode):  # devices such as /dev/null and NUL can't be truncated
            os.ftruncate(fd, 0)
    except OSError as exc:
        os.close(fd)
        raise ConfigError(f"cannot make report {path} private or empty it: {exc.strerror or exc}") from exc
    return os.fdopen(fd, "w", encoding="utf-8", newline="")


# --- mask --from ---------------------------------------------------------------------------------


def cmd_mask(args: argparse.Namespace) -> int:
    from .sources.base import ReadError
    from .sources.fs import read_regular_file

    console = Console(quiet=args.quiet, progress="none")
    out = Path(args.out)
    masker = Masker(MaskStyle(args.style), hmac_key(required=False))
    files: dict[str, dict] = {}
    spans: dict[str, list[Span]] = {}
    try:
        with open(args.source, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if not isinstance(rec, dict):
                        raise ValueError("expected a JSON object")
                    kind = rec.get("kind")
                    if kind == "file" and rec.get("status") in (Status.CLEAN.value, Status.FINDINGS.value):
                        files[_report_str(rec, "path")] = _file_record(rec)
                    elif kind == "finding":
                        spans.setdefault(_report_str(rec, "path"), []).append(_finding_span(rec))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    raise ConfigError(
                        f"report {args.source} line {lineno} is not a valid pii-scan record: {exc}"
                    ) from exc
    except OSError as exc:
        raise ConfigError(f"cannot read report {args.source}: {exc}") from exc

    from .entities import DEFAULT_SEVERITY
    from .models import Severity

    o = out.resolve()
    for f in files:
        src = Path(f).resolve()
        # refuse any overlap: out inside a scanned file's directory, or out containing a scanned file
        if o == src or o in src.parents or src.parent == o or src.parent in o.parents:
            raise ConfigError(
                f"--out {out} overlaps the scanned files (for example {src}); choose a separate directory"
            )

    rules = list(BUILTIN_RULES)
    if args.custom_regex:
        try:
            rules += load_custom_rules(Path(args.custom_regex))
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    # Re-check every file with regex rules too, so a report with deleted finding lines can't leave
    # values unmasked. AWS-only detections still come from the report.
    recheck = RegexDetector(rules)

    written = failed = 0
    for path, rec in files.items():
        file_spans = spans.get(path, [])
        try:
            data = read_regular_file(path, rec["size"] + 1)
            if hashlib.sha256(data).hexdigest() != rec["sha256"]:
                raise ValueError("file changed since the scan")
            text = decode(data, rec["encoding"])
            if any(s.end > len(text) for s in file_spans):
                raise ValueError("the report has findings beyond the end of the file")
            all_spans = dedupe([*file_spans, *recheck.detect(text)])
            if not all_spans and args.findings_only:
                continue
            dest = safe_output_path(out, rec["relpath"] or Path(path).name)
            if all_spans:
                regions = merge(all_spans, lambda t: DEFAULT_SEVERITY.get(t, Severity.HIGH))
                masked = masker.apply(text, regions)
                verify_masked(text, all_spans, masked)
                write_atomic(dest, encode_like(masked, rec["encoding"]))
            else:
                write_atomic(dest, data)
            written += 1
        except (ReadError, OSError, ValueError, DetectorError) as exc:
            failed += 1
            console.error(f"{path}: not masked: {exc}")
    console.info(f"Masked copies: {written:,} written, {failed:,} failed, under {out}.")
    return EXIT_INCOMPLETE if failed else EXIT_OK


def _report_str(rec: dict, key: str) -> str:
    value = rec[key]
    if not isinstance(value, str):
        raise TypeError(f"{key!r} must be a string")
    return value


def _report_int(rec: dict, key: str) -> int:
    value = rec[key]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TypeError(f"{key!r} must be a non-negative integer")
    return value


def _file_record(rec: dict) -> dict:
    """The fields mask --from relies on, checked so a damaged report stops the run instead of crashing it."""
    _report_int(rec, "size")
    if not re.fullmatch(r"[0-9a-f]{64}", _report_str(rec, "sha256")):
        raise ValueError("'sha256' must be 64 hex characters")
    if _report_str(rec, "encoding") not in ENCODINGS:
        raise ValueError(f"unknown encoding {rec['encoding']!r}")
    _report_str(rec, "relpath")
    return rec


def _finding_span(rec: dict) -> Span:
    start, end = _report_int(rec, "start"), _report_int(rec, "end")
    if end <= start:
        raise ValueError("'end' must be greater than 'start'")
    score = rec["score"]
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        raise TypeError("'score' must be a number")
    return Span(start, end, _report_str(rec, "type"), float(score), _report_str(rec, "detector"))


# --- doctor --------------------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    from .chunking import api_safe
    from .detectors.aws import AwsSettings
    from .entities import COMPREHEND_TYPES

    console = Console(progress="none")
    layers = [x.strip() for x in args.layers.split(",") if x.strip()]
    settings = AwsSettings(region=args.region, profile=args.profile, guardrail_id=args.guardrail_id,
                           guardrail_version=args.guardrail_version, language=args.language)  # fmt: skip
    ok = True
    try:
        aws = AwsSession(settings)
        ident = aws.identity()
        console.info(f"ok: credentials for account {ident['account']} ({ident['arn']}) in {ident['region']}")
    except DetectorError as exc:
        console.error(str(exc))
        return EXIT_USAGE

    canary = "\U0001f600\U0001f600 Contact jane.doe@example.com today."
    safe = api_safe(canary)
    expect = canary.index("jane.doe@example.com")
    types = frozenset(COMPREHEND_TYPES)
    for name in layers:
        try:
            if name == "contains":
                got = ContainsScreen(aws, types, 0.0).screen(safe)
                console.info(f"ok: contains returned {sorted(got) or 'no labels'}")
            elif name == "detect":
                spans = ComprehendDetector(aws, types, 0.0).detect(safe)
                email = [x for x in spans if x.type == "EMAIL"]
                if email and email[0].start == expect:
                    console.info("ok: detect offsets align with pii-scan's character model")
                else:
                    ok = False
                    console.error(f"detect offsets do not align (expected EMAIL at {expect}, got {email})")
                raw = ComprehendDetector(aws, types, 0.0).detect(canary)
                raw_email = [x.start for x in raw if x.type == "EMAIL"]
                model = {True: "code points"}.get(raw_email == [expect]) or (
                    "UTF-16 units" if raw_email == [expect + 2] else "an unknown unit"
                )
                console.info(f"info: without pii-scan's normalization, the service counts offsets in {model}")
            elif name == "guardrails":
                spans = GuardrailsDetector(aws, types).detect(safe)
                emails = [x for x in spans if x.type == "EMAIL" and x.start == expect]
                if emails:
                    console.info("ok: guardrails detected and located the test email")
                else:
                    ok = False
                    console.error("guardrails did not detect the test email; enable the EMAIL PII entity for "
                                  f"inputs on the guardrail (located {len(spans)} other match(es))")
            else:
                console.error(f"unknown layer {name!r}")
                ok = False
        except DetectorError as exc:
            ok = False
            console.error(f"{name}: {exc}")
    return EXIT_OK if ok else EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
