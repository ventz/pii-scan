"""Settings: defaults < config file < command line. Invalid configuration always stops the run."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .detectors.aws import AwsSettings
from .entities import COMPREHEND_TYPES, DEFAULT_SEVERITY, validate_type_names
from .masking import MaskStyle
from .models import Severity

LAYERS = ("regex", "contains", "guardrails", "detect")
SCREEN_LAYERS = frozenset({"contains"})

DEFAULT_EXCLUDED_DIRS = (
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".snapshot", "~snapshot", "$RECYCLE.BIN",
    "System Volume Information", ".Trashes", ".Spotlight-V100", ".fseventsd", ".TemporaryItems",
    "lost+found",
)  # fmt: skip
DEFAULT_EXCLUDED_EXTENSIONS = (
    ".min.js", ".map", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf",
)  # fmt: skip
DEFAULT_EXCLUDED_FILES = (".DS_Store", "Thumbs.db", "desktop.ini")

# Comprehend types that are mostly noise in general scans; opt in via entity_types.
NOISY_TYPES = frozenset({"DATE_TIME", "URL", "AGE"})

# Legacy (1.0) config keys that no longer do anything.
_IGNORED_LEGACY_KEYS = {"max_bytes", "batch_size", "max_retries", "retry_delay", "text_check_blocksize",
                        "context_window"}  # fmt: skip


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    # what to scan
    paths: tuple[str, ...] = (".",)
    scan_all: bool = False
    base: str | None = None
    trust_repo: bool = False
    restricted_config: bool = False
    same_filesystem: bool = False
    binary_policy: str = "skip"  # skip | fail
    # detection
    layers: tuple[str, ...] = ("regex",)
    entity_types: frozenset[str] = COMPREHEND_TYPES - NOISY_TYPES
    min_confidence: float = 0.85
    screen_threshold: float = 0.5
    severity: dict[str, Severity] = field(default_factory=lambda: dict(DEFAULT_SEVERITY))
    validation_patterns: dict[str, str] = field(default_factory=dict)
    custom_rules: Path | None = None
    max_matches_per_rule: int = 10_000
    aws: AwsSettings = field(default_factory=AwsSettings)
    # policy
    fail_on: Severity | None = Severity.HIGH  # None = never fail on findings
    allow_incomplete: bool = False
    baseline: Path | None = None
    write_baseline: Path | None = None
    # performance
    workers: int = 16
    max_file_size: int = 10_000_000
    cache: Path | None = None
    # excludes
    exclude_dirs: tuple[str, ...] = DEFAULT_EXCLUDED_DIRS
    exclude_extensions: tuple[str, ...] = DEFAULT_EXCLUDED_EXTENSIONS
    exclude_globs: tuple[str, ...] = ()
    exclude_files: tuple[str, ...] = DEFAULT_EXCLUDED_FILES
    # output
    output: str = "text"  # text | json | jsonl | csv | sarif
    report: Path | None = None
    show_values: bool = False
    github: bool = False
    progress: str = "auto"  # auto | lines | none
    verbose: bool = False
    quiet: bool = False
    # masking
    mask_out: Path | None = None
    mask_style: MaskStyle = MaskStyle.LABEL
    mask_findings_only: bool = False
    warnings: tuple[str, ...] = ()

    @property
    def remote_layers(self) -> tuple[str, ...]:
        return tuple(layer for layer in self.layers if layer != "regex")

    def severity_of(self, entity_type: str) -> Severity:
        return self.severity.get(entity_type, Severity.HIGH)

    def validate(self) -> Settings:
        if not self.layers:
            raise ConfigError("at least one layer is required")
        for layer in self.layers:
            if layer not in LAYERS:
                raise ConfigError(f"unknown layer {layer!r} (expected: {', '.join(LAYERS)})")
        remote = self.remote_layers
        if remote and remote[-1] in SCREEN_LAYERS:
            raise ConfigError("the last AWS layer must be a detector (guardrails or detect), not 'contains'")
        if "guardrails" in remote and not self.aws.guardrail_id:
            raise ConfigError("the guardrails layer needs --guardrail-id")
        if not 0.0 <= self.min_confidence <= 1.0 or not 0.0 <= self.screen_threshold <= 1.0:
            raise ConfigError("confidence thresholds must be between 0.0 and 1.0")
        if self.workers < 1:
            raise ConfigError("workers must be at least 1")
        if self.max_file_size < 1:
            raise ConfigError("max_file_size must be positive")
        if self.max_matches_per_rule < 1:
            raise ConfigError("max_matches_per_rule must be at least 1")
        if min(self.aws.tps_contains, self.aws.tps_detect, self.aws.guardrail_chars_per_second) <= 0:
            raise ConfigError("AWS rate limits (tps_contains, tps_detect, guardrail_chars_per_second) must be positive")
        if self.output not in {"text", "json", "jsonl", "csv", "sarif"}:
            raise ConfigError(f"unknown output format {self.output!r}")
        if self.progress not in {"auto", "lines", "none"}:
            raise ConfigError(f"unknown progress mode {self.progress!r}")
        if self.binary_policy not in {"skip", "fail"}:
            raise ConfigError("binary policy must be 'skip' or 'fail'")
        if self.show_values and in_ci():
            raise ConfigError("--show-values is refused in CI (values would land in build logs)")
        if self.aws.max_chars is not None and self.aws.max_chars < 1:
            raise ConfigError("--aws-max-chars must be positive")
        try:
            validate_type_names(self.entity_types)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        if self.mask_out is not None:
            out = self.mask_out.resolve()
            for p in self.paths:
                root = Path(p).resolve()
                if out == root or root in out.parents or out in root.parents:
                    raise ConfigError(f"--mask-out {self.mask_out} must not overlap the scanned path {p}")
        return self


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


_CI_MARKERS = ("GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "TF_BUILD", "BUILDKITE", "CIRCLECI",
               "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID")  # fmt: skip


def in_ci() -> bool:
    return _truthy(os.environ.get("CI")) or any(os.environ.get(k) for k in _CI_MARKERS)


def parse_severity_or_never(value: str) -> Severity | None:
    v = value.strip().lower()
    if v == "never":
        return None
    if v == "any":
        return Severity.LOW
    return Severity.parse(v)


def _csv(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [str(v).strip() for v in value if str(v).strip()]
    raise ConfigError(f"expected a list or comma-separated string, got {type(value).__name__}")


def load_config_file(path: Path, base: Settings, *, restricted: bool = False) -> Settings:
    """Apply a JSON config file (version 1 schema, or the 1.0 flat keys) on top of `base`.

    Any invalid value (wrong type, unknown enum value) becomes a ConfigError, which exits 2.
    With `restricted`, the file is treated as untrusted (for example it comes from the pull request
    being scanned): it may only add custom rules or raise severities.
    """
    try:
        return _load_config_file(path, base, restricted)
    except ConfigError:
        raise
    except (ValueError, TypeError, AttributeError) as exc:
        raise ConfigError(f"{path}: invalid value: {exc}") from exc


_RESTRICTED_ALLOWED_KEYS = frozenset({"version", "severity", "critical_entity_types", "regex_patterns", "custom_rules"})


def _load_config_file(path: Path, base: Settings, restricted: bool) -> Settings:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a JSON object")
    if restricted:
        blocked = sorted(set(raw) - _RESTRICTED_ALLOWED_KEYS)
        if blocked:
            raise ConfigError(f"{path}: with --restricted-config the file may only add rules or raise severities; "
                              f"not allowed: {', '.join(blocked)}")  # fmt: skip

    warnings = list(base.warnings)
    s: dict[str, Any] = {}
    aws: dict[str, Any] = {}
    severity = dict(base.severity)
    cfg_dir = path.parent

    def take(key: str) -> Any:
        return raw.pop(key, None)

    raw.pop("version", None)

    # --- 1.0 flat keys (still accepted) -------------------------------------------------------
    if (v := take("max_workers")) is not None:
        s["workers"] = int(v)
    if (v := take("min_confidence_score")) is not None:
        s["min_confidence"] = float(v)
    if (v := take("excluded_dirs")) is not None:
        s["exclude_dirs"] = tuple(dict.fromkeys([*base.exclude_dirs, *_csv(v)]))
    if (v := take("excluded_extensions")) is not None:
        s["exclude_extensions"] = tuple(dict.fromkeys([*base.exclude_extensions, *_csv(v)]))
    if (v := take("critical_entity_types")) is not None:
        names = set(_csv(v))
        _validate_names(names, path)
        severity.update({t: Severity.CRITICAL for t in names})
    if (v := take("security_relevant_entity_types")) is not None:
        names = set(_csv(v))
        _validate_names(names, path)
        s["entity_types"] = frozenset(names & COMPREHEND_TYPES) or base.entity_types
    if (v := take("regex_patterns")) is not None:
        warnings.append(f"{path}: 'regex_patterns' is deprecated; move patterns to a custom rules file")
        s["_legacy_regex_patterns"] = v
    for key in list(raw):
        if key in _IGNORED_LEGACY_KEYS:
            raw.pop(key)
            warnings.append(f"{path}: '{key}' is no longer used and was ignored")

    # --- version 1 keys ----------------------------------------------------------------------
    if (v := take("layers")) is not None:
        s["layers"] = tuple(_csv(v))
    if (v := take("fail_on")) is not None:
        s["fail_on"] = parse_severity_or_never(str(v))
    if (v := take("min_confidence")) is not None:
        s["min_confidence"] = float(v)
    if (v := take("screen_threshold")) is not None:
        s["screen_threshold"] = float(v)
    if (v := take("entity_types")) is not None:
        names = set(_csv(v))
        _validate_names(names, path)
        s["entity_types"] = frozenset(names)
    if (v := take("severity")) is not None:
        if not isinstance(v, dict):
            raise ConfigError(f"{path}: 'severity' must map severity names to type lists")
        for level, names in v.items():
            sev = Severity.parse(level)
            names_set = set(_csv(names))
            _validate_names(names_set, path, allow_custom=True)
            if restricted:
                lowered = sorted(t for t in names_set if sev < severity.get(t, Severity.HIGH))
                if lowered:
                    raise ConfigError(f"{path}: with --restricted-config severities can only be raised; "
                                      f"'{level}' would lower {', '.join(lowered)}")  # fmt: skip
            severity.update({t: sev for t in names_set})
    if (v := take("validation_patterns")) is not None:
        if not isinstance(v, dict):
            raise ConfigError(f"{path}: 'validation_patterns' must be an object")
        _validate_names(set(v), path)
        s["validation_patterns"] = {str(k): str(p) for k, p in v.items()}
    if (v := take("custom_rules")) is not None:
        s["custom_rules"] = (cfg_dir / str(v)).resolve()
    if (v := take("exclude")) is not None:
        if not isinstance(v, dict):
            raise ConfigError(f"{path}: 'exclude' must be an object")
        replace_defaults = bool(v.pop("replace_defaults", False))
        for key, attr in (("dirs", "exclude_dirs"), ("extensions", "exclude_extensions"),
                          ("globs", "exclude_globs"), ("files", "exclude_files")):  # fmt: skip
            if key in v:
                start = () if replace_defaults else s.get(attr, getattr(base, attr))
                s[attr] = tuple(dict.fromkeys([*start, *_csv(v.pop(key))]))
        if v:
            raise ConfigError(f"{path}: unknown key(s) in 'exclude': {', '.join(sorted(v))}")
    if (v := take("limits")) is not None:
        if not isinstance(v, dict):
            raise ConfigError(f"{path}: 'limits' must be an object")
        for key, attr in (("workers", "workers"), ("max_file_size", "max_file_size"),
                          ("max_matches_per_rule", "max_matches_per_rule")):  # fmt: skip
            if key in v:
                s[attr] = int(v.pop(key))
        if v:
            raise ConfigError(f"{path}: unknown key(s) in 'limits': {', '.join(sorted(v))}")
    if (v := take("max_file_size")) is not None:
        s["max_file_size"] = int(v)
    if (v := take("aws")) is not None:
        if not isinstance(v, dict):
            raise ConfigError(f"{path}: 'aws' must be an object")
        allowed = set(AwsSettings.__dataclass_fields__)
        unknown = set(v) - allowed
        if unknown:
            raise ConfigError(f"{path}: unknown key(s) in 'aws': {', '.join(sorted(unknown))}")
        aws.update(v)
    if (v := take("mask")) is not None:
        if not isinstance(v, dict):
            raise ConfigError(f"{path}: 'mask' must be an object")
        if "style" in v:
            s["mask_style"] = MaskStyle(v.pop("style"))
        if "findings_only" in v:
            s["mask_findings_only"] = bool(v.pop("findings_only"))
        if v:
            raise ConfigError(f"{path}: unknown key(s) in 'mask': {', '.join(sorted(v))}")

    if raw:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(sorted(raw))}")

    legacy_patterns = s.pop("_legacy_regex_patterns", None)
    result = replace(base, **s, severity=severity, warnings=tuple(warnings))
    if aws:
        result = replace(result, aws=replace(result.aws, **aws))
    if legacy_patterns:
        object.__setattr__(result, "_legacy_regex_patterns", legacy_patterns)
    return result


def _validate_names(names: set[str], path: Path, *, allow_custom: bool = False) -> None:
    try:
        validate_type_names(names, allow_custom=allow_custom)
    except ValueError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
