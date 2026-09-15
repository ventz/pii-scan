# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-09-15

A rewrite focused on correctness, scale, and a new masking feature.

### Breaking changes

- **Fail closed.** A file that could not be fully analyzed (AWS error, throttling after retries,
  unreadable, undecodable, too large) is reported as *not scanned* and the run exits `3`.
  Previously these files were silently treated as clean. Use `--allow-incomplete` to exit `0`
  anyway (the summary still lists them).
- **AWS layers are opt-in.** The default is regex-only, which sends nothing to AWS and costs
  nothing. Enable AWS with `--aws` (shorthand for `--layers regex,contains,detect`), or choose
  layers explicitly with `--layers`.
- **`--fail-on high` by default.** Only findings at or above the threshold fail the run; the
  1.0 behavior (fail on any finding) is `--fail-on any`.
- **Values are never printed by default.** Outputs show typed placeholders such as
  `[SSN, 11 chars]`. `--show-values` prints raw values and is refused when `CI` is set.
- **Exit codes:** `0` passed, `1` findings, `2` usage or configuration error, `3` incomplete,
  `130` interrupted. Invalid configuration (unknown keys, unknown entity types, bad regex) now
  stops the run instead of being ignored.
- **Changed-files mode** diffs against the merge base and includes uncommitted and untracked
  files. When no base can be found it exits `2` instead of silently scanning nothing.
- `--output json` is now a single valid JSON document; human-readable status goes to stderr.

### Added

- Masking: `--mask-out DIR` writes masked copies with `label`, `generic`, `stars`, `partial`, or
  `hash` (keyed HMAC pseudonym) styles, and `pii-scan mask --from report.jsonl` applies a saved
  report later after verifying each file is unchanged.
- Layered AWS detection: `contains` (Comprehend ContainsPiiEntities screen), `guardrails`
  (Bedrock ApplyGuardrail), and `detect` (Comprehend DetectPiiEntities), each running only where
  the previous layer found something. Per-API rate limits and a cost estimate in the summary.
- `--aws` flag: shorthand for `--layers regex,contains,detect`.
- `pii-scan doctor` checks credentials, each layer, and Comprehend offset alignment, and fails the
  guardrails check unless a test email is actually detected.
- The guardrails layer stops the run (exit `2`) when the guardrail has no sensitive information
  filter enabled for inputs, instead of reporting every file clean.
- Output formats `jsonl` and `sarif`, `--report FILE`, and `--github` annotations plus a job summary.
- Resume cache (`--cache FILE`) that skips unchanged files on re-runs.
- Baselines (`--write-baseline`, `--baseline`) for accepting known findings.
- Built-in rules with validators: Luhn for cards, SSN area/group/serial rules, AWS keys, private
  keys, GitHub/Slack/Stripe/Google tokens, JWTs, bearer tokens, connection-string passwords.
- Encoding detection (UTF-8, UTF-16/32 with BOM, Windows-1252) with byte-exact round trips, so
  masked copies keep their encoding and line endings.
- Configuration schema `version: 1` with `layers`, `severity`, `exclude`, `limits`, `aws`, `mask`.
  The 1.0 flat keys are still accepted.
- Test suite (pytest) and packaging with a `pii-scan` console script.

### Fixed

- Symlinks, FIFOs, and device files are never opened; reads are bounded.
- Non-ASCII UTF-8 and UTF-16 files are no longer skipped as binary.
- Chunk offsets no longer drift on multi-byte text, and entities crossing chunk boundaries are
  found via overlapping windows.
- Overlapping findings are merged before masking, so replacements never corrupt text or leak
  the tail of a value.
- Invalid entity names in the sample configuration (`CREDIT_CARD`, `PHONE_NUMBER`).
- Git paths are resolved from the repository root and read with `-z`, so subdirectory scans and
  non-ASCII file names work.
- The GitHub Action: inputs are passed through the environment (no `eval`), actions are pinned by
  commit SHA, the script path is correct, and credentials come from the caller's job.

### Security

- `--restricted-config` (always used by the GitHub Action): configuration and custom rules files
  from the scanned tree may only add rules or raise severities.
- Changed-files mode refuses repositories whose own `.git/config` sets filters, includes,
  fsmonitor, or diff commands, unless `--trust-repo` is given.
- Reads verify that the opened file is still under the scan root.
- `--aws-max-chars` sets a cost ceiling for AWS layers.
- A file where one rule exceeds `max_matches_per_rule` (default 10,000) is reported as not scanned,
  never partially masked.
- `pii-scan mask --from` refuses output directories that overlap the scanned files, masks findings
  suppressed by a baseline, and re-runs regex rules so a tampered report can't leave values unmasked.
- The resume cache stores findings from before the baseline, is skipped with `--show-values`, keys
  on change time, and is created with owner-only permissions. Reports refuse symlinks.
- The `jwt` and `private-key-block` patterns no longer backtrack on adversarial input.
- The GitHub Action pins its uv version and build backend, installs without dev dependencies,
  writes the report outside the workspace, and uploads SARIF only for complete scans.
- `PII_SCAN_HMAC_KEY` must be at least 16 bytes; `hash` masks use 12 hex characters.

### Removed

- The unused `batch_size`, `max_retries`, `retry_delay`, `text_check_blocksize`, and
  `context_window` settings (ignored with a warning if present).
- The `Harvard ID` example pattern, which matched any eight-digit number.

## [1.0.0] - 2025-10-20

- Path scanning, regex caching, retry with backoff, and documentation.
