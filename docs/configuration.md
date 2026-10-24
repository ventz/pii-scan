# Configuration Reference

> **Audience**: anyone tuning pii-scan. Settings are applied in order:
> built-in defaults, then `--config FILE`, then command-line flags.

- [Commands](#commands)
- [Scan flags](#scan-flags)
- [Output](#output)
- [Configuration file](#configuration-file)
- [1.0 configuration keys](#10-configuration-keys)
- [Custom regex rules](#custom-regex-rules)
- [Severities](#severities)
- [Default excludes](#default-excludes)
- [Environment variables](#environment-variables)

## Commands

| Command | Purpose |
|---------|---------|
| `pii-scan [scan] [PATH ...]` | Scan files (the `scan` word is optional) |
| `pii-scan mask --from REPORT.jsonl --out DIR` | Write masked copies from a saved report ([Masking](masking.md)) |
| `pii-scan doctor` | Check credentials, layers, and offset alignment |
| `pii-scan version` | Print the version |

## Scan flags

### What to scan

| Flag | Default | Description |
|------|---------|-------------|
| `PATH ...` | `.` | Files or directories |
| `--all` | off | Scan everything under the paths instead of only git changes |
| `--base REF` | auto | Git ref to diff against (changed-files mode) |
| `--trust-repo` | off | Allow changed-files mode when the repository's own git config (`.git/config`, or a worktree's `config.worktree`) sets filters, includes, fsmonitor, or diff commands, which could run commands (refused by default). Submodules are never examined |
| `--exclude-dirs A,B` | see [defaults](#default-excludes) | Directory names to skip, added to the defaults |
| `--exclude-exts .a,.b` | see defaults | File suffixes to skip, added to the defaults |
| `--exclude GLOB` | none | Root-relative glob to skip, repeatable (`archive/**`) |
| `--max-file-size BYTES` | `10000000` | Larger files are reported as not scanned |
| `--same-filesystem` | off | Do not descend into other mounts |
| `--binary skip\|fail` | `skip` | Binary files are skipped, or counted as not scanned |

### Detection

| Flag | Default | Description |
|------|---------|-------------|
| `--aws` | off | Use AWS detection: shorthand for `--layers regex,contains,detect` (can't be combined with `--layers`) |
| `--layers LIST` | `regex` | Any of `regex,contains,guardrails,detect`, in order ([Detection Layers](detection-layers.md)) |
| `--config FILE` | none | JSON configuration file |
| `--custom-regex FILE` | none | Custom regex rules ([format](#custom-regex-rules)) |
| `--restricted-config` | off | Treat `--config` and `--custom-regex` as untrusted: they may only add rules or raise severities, and custom rules must be RE2 syntax (used by the GitHub Action) |
| `--min-confidence F` | `0.85` | Minimum score for `detect` results |
| `--screen-threshold F` | `0.5` | Minimum `contains` label score to escalate a chunk |
| `--entity-types LIST` | all except `DATE_TIME,URL,AGE` | AWS entity types to report |
| `--region R` | AWS default | Region for AWS layers |
| `--profile P` | AWS default | AWS profile |
| `--language CODE` | `en` | Language sent to AWS (`detect` supports `en` and `es`) |
| `--guardrail-id ID` | none | Bedrock guardrail ID or ARN (required for `guardrails`) |
| `--guardrail-version V` | `DRAFT` | Guardrail version |
| `--max-tps-contains N` | `20` | ContainsPiiEntities requests per second |
| `--max-tps-detect N` | `40` | DetectPiiEntities requests per second |
| `--aws-max-chars N` | none | Cost ceiling: stop the run (exit `2`) once N characters have been sent to AWS |

### Policy

| Flag | Default | Description |
|------|---------|-------------|
| `--fail-on LEVEL` | `high` | `critical`, `high`, `medium`, `low`, `any`, or `never` |
| `--allow-incomplete` | off | Exit `0` even if some files could not be scanned |
| `--baseline FILE` | none | Ignore findings recorded in this baseline |
| `--write-baseline FILE` | none | Record all current findings as a baseline |

Baselines key findings by path (relative to the working directory, so the same baseline works in
`--all` and changed-files mode), type, and a keyed fingerprint. Both flags need
`PII_SCAN_HMAC_KEY` (at least 16 bytes) set to the same value on every run.

### Masking

| Flag | Default | Description |
|------|---------|-------------|
| `--mask-out DIR` | none | Write masked copies under DIR (must not overlap the scanned paths) |
| `--mask-style STYLE` | `label` | `label`, `generic`, `stars`, `partial`, or `hash` |
| `--mask-findings-only` | off | Write only files that had findings |

### Performance

| Flag | Default | Description |
|------|---------|-------------|
| `--workers N` | `16` | File worker threads (raise for network shares) |
| `--cache FILE` | none | SQLite cache that skips unchanged files on re-runs: a file is rescanned when its path, size, modification or change time, or the configuration changes. Created owner-only; keep it on local disk. Not used with `--mask-out` or `--show-values`. On Windows each file is opened once more to read its NTFS change time |

## Output

| Flag | Default | Description |
|------|---------|-------------|
| `--output FORMAT` | `text` | `text`, `json`, `jsonl`, `csv`, or `sarif` |
| `--report FILE` | stdout | Write the formatted output to a file (mode `0600`; on Windows, an ACL for the current user and SYSTEM only) |
| `--github` | off | Add GitHub annotations and a job summary, and write a `complete=true` or `complete=false` step output (every file scanned and the report whole) to `$GITHUB_OUTPUT` |
| `--show-values` | off | Print raw values (refused when `CI` is set) |
| `--progress auto\|lines\|none` | `auto` | Progress on stderr: a redrawn line on a terminal, plain lines every 30 s otherwise |
| `-v`, `--verbose` | off | More detail on stderr |
| `-q`, `--quiet` | off | Only findings and errors |

stdout carries only the selected format; progress, warnings, errors, and the summary go to stderr.
A `--report` file is always UTF-8. On Windows, a report on stdout is UTF-8 too, with the same
bytes as a `--report` file, whatever the console code page or `PYTHONIOENCODING`; elsewhere
stdout follows the locale. `--github` annotations (on stdout, or on stderr when stdout carries
the report) are UTF-8 on Windows too, as GitHub expects. Windows PowerShell 5.1 re-encodes `>`
redirection (as UTF-16), so use `--report` there; `cmd.exe`, Git Bash, and PowerShell 7.4+ keep
the bytes.
Messages have no color or emoji; control characters in paths are escaped. On Windows, when
`--github` annotations go to stderr, the messages there are UTF-8 too.

| Format | Shape | Best for |
|--------|-------|----------|
| `text` | `path:line:col: SEVERITY TYPE (detector score): preview` | Terminals, editors |
| `jsonl` | `file` and `finding` records, then one `summary` record | Large scans, `pii-scan mask --from` |
| `json` | One document with the summary and files that had findings or errors | Small scans |
| `csv` | One row per finding, formula-safe | Spreadsheets |
| `sarif` | SARIF 2.1.0, capped at 25,000 results | GitHub code scanning |

## Configuration file

Every key is optional. Unknown keys, unknown entity types, and invalid values stop the run with
exit code `2`.

```json
{
  "version": 1,
  "layers": ["regex", "contains", "detect"],
  "fail_on": "high",
  "min_confidence": 0.85,
  "screen_threshold": 0.5,
  "entity_types": ["NAME", "ADDRESS", "EMAIL", "PHONE", "SSN", "CREDIT_DEBIT_NUMBER"],
  "severity": { "critical": ["NAME"], "low": ["EMAIL"] },
  "validation_patterns": { "AWS_ACCESS_KEY": "(?:AKIA|ASIA)[0-9A-Z]{16}" },
  "custom_rules": "custom_regex_patterns.json",
  "exclude": { "dirs": ["dist"], "extensions": [".png"], "globs": ["archive/**"], "files": [], "replace_defaults": false },
  "limits": { "workers": 32, "max_file_size": 10000000, "max_matches_per_rule": 10000 },
  "aws": {
    "region": "us-east-1", "profile": null, "endpoint_url": null, "language": "en",
    "tps_contains": 20, "tps_detect": 40, "guardrail_chars_per_second": 20000,
    "guardrail_id": null, "guardrail_version": "DRAFT", "max_attempts": 8, "pool_size": 32,
    "max_chars": null
  },
  "mask": { "style": "label", "findings_only": false }
}
```

| Key | Description |
|-----|-------------|
| `layers` | Same as `--layers` |
| `fail_on` | Same as `--fail-on` |
| `min_confidence`, `screen_threshold` | Same as the flags |
| `entity_types` | AWS entity types to report |
| `severity` | Map of severity to entity types, overriding [defaults](#severities) |
| `validation_patterns` | Map of entity type to a regex that AWS matches must fully match |
| `custom_rules` | Custom rules file, relative to the configuration file |
| `exclude` | Lists added to the defaults; `replace_defaults: true` replaces them |
| `limits` | `workers`, `max_file_size`, `max_matches_per_rule` (a file where one rule matches more often is reported as not scanned, never partially masked) |
| `aws` | Region, profile, endpoint (an `https://` URL, for example a VPC endpoint), language, rate limits, guardrail, retry attempts, connection pool size, and `max_chars` (same as `--aws-max-chars`) |
| `mask` | `style` and `findings_only` |

A pull request can edit files in its own tree. When the configuration file or custom rules come
from the code being scanned, pass `--restricted-config`: the file may then only add rules
(`custom_rules`, `regex_patterns`) or raise severities (`severity`, `critical_entity_types`), and
anything else stops the run. The GitHub Action always does this.

Values must have the types used in the example above: `true`/`false` for switches, whole numbers
for counts and sizes, numbers for thresholds and rates, strings for names, and lists of strings (or
one comma-separated string) for lists. A quoted number (`"40"`), a quoted boolean (`"false"`), or
`null` for a key that has no "unset" value stops the run (exit `2`) instead of being guessed at.
Remove a key to use its default. `version` must be `1` when present.

## 1.0 configuration keys

Configuration files from 1.0 still load.

| 1.0 key | Treated as |
|---------|------------|
| `max_workers` | `limits.workers` |
| `min_confidence_score` | `min_confidence` |
| `excluded_dirs`, `excluded_extensions` | Added to `exclude.dirs`, `exclude.extensions` |
| `critical_entity_types` | `severity.critical` |
| `security_relevant_entity_types` | `entity_types` |
| `validation_patterns` | Unchanged |
| `regex_patterns` | Custom rules (deprecated, warns) |
| `max_bytes`, `batch_size`, `max_retries`, `retry_delay`, `text_check_blocksize`, `context_window` | Ignored with a warning |

## Custom regex rules

```json
{
  "rules": [
    { "id": "employee-id", "pattern": "\\bEMP-\\d{6}\\b", "severity": "medium" },
    { "id": "jdbc-password", "type": "CONNECTION_STRING",
      "pattern": "(?i)jdbc:[a-z0-9]+://[^\\s;]*;password=([^;\\s]+)", "group": 1 }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Rule name, shown in reports |
| `pattern` | yes | Python regular expression (RE2 syntax under `--restricted-config`) |
| `type` | no | A known entity type, or omitted for `CUSTOM:<id>` |
| `severity` | no | Defaults to the type's severity, or `high` for custom types |
| `group` | no | Capture group holding the sensitive value (default: whole match) |

The 1.0 format `{"Label": "pattern"}` is also accepted. If
[google-re2](https://pypi.org/project/google-re2/) is installed (`pip install 'pii-scan[re2]'`),
custom patterns compile with RE2 for linear-time matching when they don't use lookarounds or
backreferences. With `--restricted-config` there is no fallback: every custom pattern must compile
with RE2, and google-re2 must be installed, so an untrusted rule can't cause catastrophic
backtracking. The rules file must also be a regular file under the working directory, with at
most 200 rules of at most 1,000 characters each.

RE2 and Python `re` differ in a few classes: in RE2, `\d`, `\w`, `\s`, and `\b` are ASCII-only,
while Python treats them as Unicode (so `\d` matches Arabic-Indic digits in Python but not in
RE2). Write `[0-9]` or `\p{Nd}` explicitly when it matters.

## Severities

| Severity | Entity types |
|----------|--------------|
| critical | `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `PASSWORD`, `SSN`, `CREDIT_DEBIT_NUMBER`, `BANK_ACCOUNT_NUMBER`, `PRIVATE_KEY`, `GITHUB_TOKEN`, `SLACK_TOKEN`, `STRIPE_KEY`, `CONNECTION_STRING`, `US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER`, `INTERNATIONAL_BANK_ACCOUNT_NUMBER` |
| high | `CREDIT_DEBIT_CVV`, `CREDIT_DEBIT_EXPIRY`, `PIN`, `BANK_ROUTING`, `PASSPORT_NUMBER`, `DRIVER_ID`, UK/CA/IN national identifiers, `JWT`, `BEARER_TOKEN`, `API_KEY`, `GENERIC_SECRET`, `GOOGLE_API_KEY`, and custom rule types |
| medium | `NAME`, `ADDRESS`, `PHONE`, `EMAIL`, `USERNAME`, `SWIFT_CODE` |
| low | `DATE_TIME`, `URL`, `AGE`, `IP_ADDRESS`, `MAC_ADDRESS`, `LICENSE_PLATE`, `VEHICLE_IDENTIFICATION_NUMBER` |

## Default excludes

- **Directories**: `.git .hg .svn node_modules .venv venv __pycache__ .tox .mypy_cache
  .pytest_cache .ruff_cache .snapshot ~snapshot $RECYCLE.BIN "System Volume Information" .Trashes
  .Spotlight-V100 .fseventsd .TemporaryItems lost+found`
- **Suffixes**: `.min.js .map .svg .woff .woff2 .ttf .eot .otf`
- **File names**: `.DS_Store Thumbs.db desktop.ini`
- **Always skipped**: symlinks (and on Windows junctions and other link-type reparse points), FIFOs,
  sockets, and devices. Binary files are skipped by default. Cloud placeholders whose data isn't on
  the machine are reported as not scanned (`offline_placeholder`) rather than downloaded.

Skipped files are counted by reason in the summary.

## Environment variables

| Variable | Effect |
|----------|--------|
| `PII_SCAN_HMAC_KEY` | Key for fingerprints and `hash` masking, at least 16 bytes. Required for baselines; set it to keep pseudonyms and SARIF fingerprints stable across runs. Without it, a random per-run key is used. |
| `AWS_PROFILE`, `AWS_REGION`, `AWS_DEFAULT_REGION` | Standard AWS settings, used when flags don't set them |
| `AWS_ENDPOINT_URL*` | Ignored unless `aws.endpoint_url` is set, so the environment can't redirect scanned text |
| `CI` (and `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `TF_BUILD`, `BUILDKITE`, `CIRCLECI`, and similar) | `--show-values` is refused; `CI` also makes progress default to plain lines |
| `GITHUB_STEP_SUMMARY` | Target for the job summary with `--github` |
| `GITHUB_OUTPUT` | Target for the `complete` step output with `--github` |
| `GITHUB_BASE_REF` | Used to find the diff base in pull request workflows |
