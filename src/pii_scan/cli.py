"""Command-line interface.

Exit codes: 0 passed, 1 findings at or above --fail-on, 2 usage/configuration/credential error,
3 incomplete (some files could not be scanned), 130 interrupted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import threading
from dataclasses import replace
from pathlib import Path

from . import __version__
from .console import Console
from .detectors.aws import AwsSession, ComprehendDetector, ContainsScreen, GuardrailsDetector
from .detectors.base import DetectorError
from .detectors.regex import BUILTIN_RULES, RegexDetector, Rule, load_custom_rules
from .masking import Masker, MaskStyle, safe_output_path, write_atomic
from .models import Status
from .settings import ConfigError, Settings, load_config_file, parse_severity_or_never
from .sinks import CsvSink, GithubSink, JsonlSink, JsonSink, MultiSink, SarifSink, TextSink
from .sniff import decode, encode_like
from .sources.fs import Excludes, FilesystemSource
from .sources.git import GitChangedSource, GitError
from .spans import merge
from .state import Baseline, ResultCache

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_INCOMPLETE, EXIT_INTERRUPTED = 0, 1, 2, 3, 130
COMMANDS = {"scan", "mask", "doctor", "version"}
AWS_PRESET = ("regex", "contains", "detect")

EPILOG = """\
examples:
  pii-scan --all ~/shares/finance                 regex scan of a whole tree (no AWS calls)
  pii-scan                                         scan files changed vs. origin's default branch
  pii-scan --all --aws --region us-east-1 /mnt/share   (same as --layers regex,contains,detect)
  pii-scan --all --mask-out /secure/masked /mnt/share
  pii-scan --all --output jsonl --report findings.jsonl /mnt/share
  pii-scan mask --from findings.jsonl --out /secure/masked --style hash

exit codes:
  0 passed   1 findings at or above --fail-on   2 usage or configuration error
  3 incomplete (some files could not be scanned)   130 interrupted
"""


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("what to scan")
    g.add_argument("paths", nargs="*", default=["."], help="files or directories (default: current directory)")
    g.add_argument("--all", action="store_true", help="scan everything under the paths (default: only git changes)")
    g.add_argument("--base", help="git ref to diff against in changed-files mode")
    g.add_argument("--exclude-dirs", help="comma-separated directory names to skip (added to defaults)")
    g.add_argument("--exclude-exts", help="comma-separated file suffixes to skip (added to defaults)")
    g.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="root-relative glob to skip (repeatable), e.g. 'archive/**'")
    g.add_argument("--max-file-size", type=int, metavar="BYTES", help="larger files are reported as not scanned")
    g.add_argument("--same-filesystem", action="store_true", help="do not cross into other mounts")
    g.add_argument("--binary", choices=["skip", "fail"], help="binary files: skip (default) or count as not scanned")

    g = p.add_argument_group("detection")
    g.add_argument("--aws", action="store_true",
                   help="use AWS detection (shorthand for --layers regex,contains,detect); off by default")
    g.add_argument("--layers", help="comma-separated: regex,contains,guardrails,detect (default: regex)")
    g.add_argument("--config", help="JSON configuration file")
    g.add_argument("--custom-regex", help="JSON file with custom regex rules")
    g.add_argument("--min-confidence", type=float, help="minimum score for AWS detections (default 0.85)")
    g.add_argument("--screen-threshold", type=float, help="minimum ContainsPiiEntities score to escalate (default 0.5)")
    g.add_argument("--entity-types", help="comma-separated AWS entity types to report")
    g.add_argument("--region", help="AWS region for AWS layers")
    g.add_argument("--profile", help="AWS profile for AWS layers")
    g.add_argument("--language", help="language code sent to AWS (default en)")
    g.add_argument("--guardrail-id", help="Bedrock guardrail ID or ARN (guardrails layer)")
    g.add_argument("--guardrail-version", help="Bedrock guardrail version (default DRAFT)")
    g.add_argument("--max-tps-contains", type=float, help="ContainsPiiEntities requests per second (default 20)")
    g.add_argument("--max-tps-detect", type=float, help="DetectPiiEntities requests per second (default 40)")

    g = p.add_argument_group("policy")
    g.add_argument("--fail-on", help="critical|high|medium|low|any|never (default high)")
    g.add_argument("--allow-incomplete", action="store_true", help="exit 0 even if some files could not be scanned")
    g.add_argument("--baseline", help="JSON baseline of accepted findings (needs PII_SCAN_HMAC_KEY)")
    g.add_argument("--write-baseline", help="write all current findings to this baseline file")

    g = p.add_argument_group("output")
    g.add_argument("--output", choices=["text", "json", "jsonl", "csv", "sarif"], help="format (default text)")
    g.add_argument("--report", help="write the formatted output to this file instead of stdout")
    g.add_argument("--github", action="store_true", help="also emit GitHub annotations and a job summary")
    g.add_argument("--show-values", action="store_true", help="print raw matched values (refused when CI is set)")
    g.add_argument("--progress", choices=["auto", "lines", "none"], help="progress on stderr (default auto)")
    g.add_argument("-v", "--verbose", action="store_true", help="more detail on stderr")
    g.add_argument("-q", "--quiet", action="store_true", help="only findings and errors")

    g = p.add_argument_group("masking")
    g.add_argument("--mask-out", help="write masked copies of scanned files under this directory")
    g.add_argument("--mask-style", choices=[m.value for m in MaskStyle], help="replacement style (default label)")
    g.add_argument("--mask-findings-only", action="store_true", help="only write files that had findings")

    g = p.add_argument_group("performance")
    g.add_argument("--workers", type=int, help="file worker threads (default 16)")
    g.add_argument("--cache", help="SQLite file to skip unchanged files on re-runs (keep it off the share)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-scan",
        description="Find and mask PII and secrets in files, repositories, and file shares.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"pii-scan {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan files (default command)", epilog=EPILOG,
                          formatter_class=argparse.RawDescriptionHelpFormatter)  # fmt: skip
    _add_scan_args(scan)

    mask = sub.add_parser("mask", help="write masked copies from a jsonl report")
    mask.add_argument("--from", dest="source", required=True, help="jsonl report produced by 'scan --output jsonl'")
    mask.add_argument("--out", required=True, help="output directory (must not contain the scanned files)")
    mask.add_argument("--style", choices=[m.value for m in MaskStyle], default="label")
    mask.add_argument("--findings-only", action="store_true", help="only write files that had findings")
    mask.add_argument("-q", "--quiet", action="store_true")

    doctor = sub.add_parser("doctor", help="check AWS credentials, quotas, and each configured layer")
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
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    parser = build_parser()
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


# --- scan ----------------------------------------------------------------------------------------


def settings_from_args(args: argparse.Namespace) -> Settings:
    s = Settings()
    if args.config:
        s = load_config_file(Path(args.config), s)
    aws = s.aws
    changes: dict = {"paths": tuple(args.paths or ["."]), "scan_all": args.all, "base": args.base}

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


def build_rules(s: Settings) -> list[Rule]:
    rules = list(BUILTIN_RULES)
    if s.custom_rules:
        try:
            rules += load_custom_rules(s.custom_rules)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    legacy = getattr(s, "_legacy_regex_patterns", None)
    if legacy:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(legacy, fh)
        try:
            rules += load_custom_rules(Path(fh.name))
        except ValueError as exc:
            raise ConfigError(f"regex_patterns: {exc}") from exc
        finally:
            os.unlink(fh.name)
    return rules


def config_hash(s: Settings, rules: list[Rule]) -> str:
    material = {
        "version": __version__, "layers": s.layers, "entity_types": sorted(s.entity_types),
        "min_confidence": s.min_confidence, "screen_threshold": s.screen_threshold,
        "severity": sorted((k, int(v)) for k, v in s.severity.items()),
        "validation": sorted(s.validation_patterns.items()), "max_matches": s.max_matches_per_rule,
        "rules": [(r.id, r.type, r.pattern.pattern, r.group) for r in rules],
        "language": s.aws.language, "guardrail": [s.aws.guardrail_id, s.aws.guardrail_version],
        "binary": s.binary_policy, "max_file_size": s.max_file_size,
    }  # fmt: skip
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


def hmac_key(required: bool) -> bytes | None:
    raw = os.environ.get("PII_SCAN_HMAC_KEY")
    if not raw:
        if required:
            raise ConfigError("baselines need a stable key: set PII_SCAN_HMAC_KEY (for example a repository secret)")
        return None
    return raw.encode("utf-8")


def cmd_scan(args: argparse.Namespace) -> int:
    s = settings_from_args(args)
    console = Console(quiet=s.quiet, verbose=s.verbose, progress=s.progress)
    for w in s.warnings:
        console.warn(w)

    rules = build_rules(s)
    severity = dict(s.severity)
    for r in rules:
        if r.severity is not None:
            severity[r.type] = r.severity
    s = replace(s, severity=severity)

    excludes = Excludes(s.exclude_dirs, s.exclude_extensions, s.exclude_globs, s.exclude_files)
    if s.scan_all:
        source = FilesystemSource(s.paths, excludes, max_file_size=s.max_file_size, same_filesystem=s.same_filesystem)
        source.name = "fs"  # type: ignore[attr-defined]
    else:
        if len(s.paths) != 1:
            raise ConfigError("changed-files mode takes one path; use --all to scan several")
        try:
            source = GitChangedSource(Path(s.paths[0]), s.base, excludes, max_file_size=s.max_file_size)
        except GitError as exc:
            raise ConfigError(f"{exc}. To scan a directory that is not a git checkout, add --all.") from exc
        source.name = "git"  # type: ignore[attr-defined]
        console.debug(f"diffing against {source.base}")

    stop = threading.Event()
    aws = None
    layers = []
    api_threads = 8
    if s.remote_layers:
        try:
            aws = AwsSession(replace(s.aws, pool_size=max(32, s.workers * 2)), stop)
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
        peak = max(s.aws.tps_detect if "detect" in s.remote_layers else 0,
                   s.aws.tps_contains if "contains" in s.remote_layers else 0, 4)  # fmt: skip
        api_threads = min(128, math.ceil(peak * 1.5) + 4)

    baseline = None
    key = hmac_key(required=bool(s.baseline or s.write_baseline))
    if s.baseline:
        try:
            baseline = Baseline.load(s.baseline)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    masker = Masker(s.mask_style, key)
    cache = ResultCache(s.cache, config_hash(s, rules)) if s.cache else None

    out_stream = open(s.report, "w", encoding="utf-8", newline="") if s.report else sys.stdout  # noqa: SIM115
    try:
        if s.report:
            os.chmod(s.report, 0o600)
        sink_types = {"text": TextSink, "json": JsonSink, "jsonl": JsonlSink, "csv": CsvSink, "sarif": SarifSink}
        primary = sink_types[s.output](out_stream)
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
        console.error(summary.aborted)
    if s.write_baseline:
        Baseline.write(s.write_baseline, scanner.baseline_keys)
        console.info(f"Wrote {len(scanner.baseline_keys):,} baseline entries to {s.write_baseline}")
    console.summary(summary, mask_out=str(s.mask_out) if s.mask_out else None)
    return summary.exit_code(s.allow_incomplete)


# --- mask --from ---------------------------------------------------------------------------------


def cmd_mask(args: argparse.Namespace) -> int:
    from .models import Span
    from .sources.base import ReadError
    from .sources.fs import read_regular_file

    console = Console(quiet=args.quiet, progress="none")
    out = Path(args.out)
    masker = Masker(MaskStyle(args.style), hmac_key(required=False))
    files: dict[str, dict] = {}
    spans: dict[str, list[Span]] = {}
    try:
        with open(args.source, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("kind") == "file" and rec.get("status") in (Status.CLEAN.value, Status.FINDINGS.value):
                    files[rec["path"]] = rec
                elif rec.get("kind") == "finding":
                    spans.setdefault(rec["path"], []).append(
                        Span(int(rec["start"]), int(rec["end"]), rec["type"], float(rec["score"]), rec["detector"]))
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise ConfigError(f"cannot read report {args.source}: {exc}") from exc

    from .entities import DEFAULT_SEVERITY
    from .models import Severity

    for p in {Path(f).resolve().parent for f in files}:
        o = out.resolve()
        if o == p or p in o.parents:
            raise ConfigError(f"--out {out} must not be inside the scanned tree ({p})")

    written = failed = 0
    for path, rec in files.items():
        file_spans = spans.get(path, [])
        if args.findings_only and not file_spans:
            continue
        try:
            data = read_regular_file(path, max(int(rec["size"]), 0) + 1)
            if hashlib.sha256(data).hexdigest() != rec["sha256"]:
                raise ValueError("file changed since the scan")
            dest = safe_output_path(out, rec["relpath"] or Path(path).name)
            if file_spans:
                text = decode(data, rec["encoding"])
                regions = merge(file_spans, lambda t: DEFAULT_SEVERITY.get(t, Severity.HIGH))
                write_atomic(dest, encode_like(masker.apply(text, regions), rec["encoding"]))
            else:
                write_atomic(dest, data)
            written += 1
        except (ReadError, OSError, ValueError) as exc:
            failed += 1
            console.error(f"{path}: not masked: {exc}")
    console.info(f"Masked copies: {written:,} written, {failed:,} failed, under {out}.")
    return EXIT_INCOMPLETE if failed else EXIT_OK


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
