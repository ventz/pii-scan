# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.2] - 2026-10-24

### Fixed

- **Windows: reports written to stdout are UTF-8.** `pii-scan --output jsonl > r.jsonl` used
  the console code page (often cp1252), so a non-ASCII path came out as invalid UTF-8 or as a
  `\U...` escape that breaks JSON and `pii-scan mask --from`. stdout now gets the same UTF-8 and
  line endings as a `--report` file. Other platforms are unchanged.
- **Windows: GitHub annotations are UTF-8.** With `--github` on a Windows runner, an annotation
  for a file with a non-ASCII name named the file in the console code page, so it didn't attach
  to that file. Annotations, on stdout or stderr, are now UTF-8 on Windows. This includes the
  GitHub Action, which passes `--report --github`. When annotations go to stderr, the messages
  that share it are UTF-8 too, from the first line.

## [1.2.1] - 2026-10-23

### Fixed

- **GitHub Action: the exit code is captured again.** The action's shell runs with `-e`, so a
  scan that exited non-zero ended the step before its `exit-code` output was written: SARIF was
  never uploaded for a scan with findings, and the result message was missing. The job still
  failed.
- **GitHub Action: SARIF is uploaded only when every file was scanned.** pii-scan with
  `--github` now writes a `complete` step output (`true` or `false`), which the action also
  exposes, and the upload requires it. Exit code `1` alone also covers a scan with findings that
  left some files unscanned, whose partial SARIF could have closed alerts that still exist. A
  SARIF report cut off at 25,000 results counts as incomplete too. With `allow-incomplete`, an
  incomplete scan still passes but no longer uploads SARIF.
- **GitHub Action: outside pull requests, SARIF is uploaded only with `scan-all: true`.** A
  changed-files report uploaded for a branch made code scanning close the alerts in every file
  that didn't change. The action now skips that upload and says why; run a full scan (for
  example on a schedule) for code scanning on the default branch.

## [1.2.0] - 2026-10-23

Windows support. One behavior change on macOS: see **Changed**.

### Changed

- **Cloud placeholder files are no longer downloaded to scan them.** On macOS, an iCloud Drive
  (or other File Provider) file whose data isn't stored locally ("dataless") used to be read,
  which downloaded it, and then scanned. It is now reported as not scanned
  (`offline_placeholder`), so a scan that meets one exits `3`. Make such files available offline
  first (`brctl download <path>`), or pass `--allow-incomplete`. OneDrive online-only and other
  offline or recall-on-access files on Windows are handled the same way.

### Security

- **Windows gets the same file protections as Linux and macOS.** Before, the check that an
  opened file is under the scan root was skipped on Windows, symlinks were only checked before
  opening (a race), junctions weren't treated as links at all, and `chmod` didn't make reports,
  caches, baselines, or masked copies private. Now:
  - symlinks, junctions, and other name-surrogate reparse points are skipped while walking and
    refused when reading, and every opened file's final path must be under the scan root;
  - reports, caches, baselines, masked files, and masked folders get a protected ACL (current
    user and SYSTEM only) before any data is written;
  - reports, temporary files, masked folders, and the cache database are created with that ACL,
    so no other account can open them in the moment before it would otherwise be applied;
  - a report path that is a link, or a cloud or deduplicated file, is refused without truncating
    or writing through it;
  - files are opened, and folders listed, by their exact name (`\\?\` form), so a name with a
    trailing dot or space, or a file named like a device, is read as itself and not as another
    file or a device (`.` and `..` in a path are resolved first, so relative paths such as
    `--cache ..\c.sqlite` work);
  - masked copies whose names Windows can't store safely (a `:` that would create an alternate
    data stream, device names such as `CON`, a trailing dot or space) are not written.
- git's hooks path is now the platform's null device on every system.
- git also runs with `GIT_ALLOW_PROTOCOL=none`, which overrides every `protocol.*.allow` setting
  from any configuration scope, so no transport can be used, including ones the command-line
  settings don't name.
- In changed-files mode, a changed file that exists but can't be examined (access denied, or a
  sharing violation on Windows) is reported as not scanned (exit `3`); only a file deleted since
  the diff is left out.
- An existing report file is made private before it is emptied, so a report that can't be made
  private is left untouched instead of truncated.
- Rule IDs in text and CSV output are escaped like paths and previews, so a custom rule ID from
  a scanned tree's config can't send terminal control characters or start a spreadsheet formula.
- The build backend and its dependencies (hatchling, packaging, pathspec, pluggy, tomlkit,
  trove-classifiers) are pinned to exact versions, because the GitHub Action builds pii-scan
  inside jobs that may hold credentials.
- With `--cache` on Windows, the NTFS change time is used, since `st_ctime` there is the creation
  time: an edited file whose old modification time was restored is no longer served from the
  cache.

### Fixed

- `--same-filesystem` on Windows no longer skips every subfolder (directory entries report a
  device number of 0 there).
- `--report /dev/null` (or `NUL`) works again.

### Added

- Windows support (see [Scanning File Shares](docs/scanning-shares.md#windows)), with a Windows
  CI job. Cloud placeholders (OneDrive online-only files and folders, offline or
  recall-on-access files, and iCloud Drive dataless files on macOS) are reported as not scanned
  (`offline_placeholder`) instead of being downloaded during a scan.

## [1.1.1] - 2026-10-21

### Security

- **Changed-files mode now checks every repository config git reads.** A filter set in a linked
  worktree's `config.worktree` (`.git/worktrees/<name>/config.worktree`) was not checked, so a
  scan without `--trust-repo` could run a command from an untrusted checkout. pii-scan now asks
  git for its configuration with `git config --list --show-scope` and refuses risky keys in the
  `local` and `worktree` scopes, whichever file they come from. This needs git 2.26 or later.
- **Submodules are never examined.** To decide whether a submodule changed, git ran itself inside
  it, where the submodule's own config (`.git/modules/<name>/config`) could set a filter that ran
  a command, with or without `--trust-repo`. git now runs with submodules ignored. pii-scan never
  scanned files inside submodules, so results don't change.
- **git never fetches or uses a transport.** In a partial clone, repository config could allow the
  `ext::` transport, and the on-demand fetch of a missing object during the diff then ran the
  command in the remote URL, with or without `--trust-repo`. The `ext`, `file`, `git`, `ssh`,
  `http`, and `https` transports, and the `protocol.allow` default, are now set to `never` on the
  command line (where repository config can't re-enable them), on-demand fetching is off
  (`GIT_NO_LAZY_FETCH`), and repository config that sets `protocol.*`, `core.gitProxy`, or a
  remote's `uploadpack`/`receivepack` is refused without `--trust-repo`. A partial clone missing an
  object the diff needs now stops the scan (exit `2`) instead of fetching it.
- **Only the usual repository layout is accepted** without `--trust-repo`: the git directory must
  be `<top>/.git` (or the file a linked worktree uses), and git ignores directories that merely
  look like a bare repository (`safe.bareRepository=explicit`). The diff also runs with
  `--no-ext-diff --no-textconv`.
- **git is run by absolute path** from the absolute entries of `PATH`, never from the scanned
  repository or a relative `PATH` entry. On Windows a bare `git` is looked up in the current
  directory first, so a `git.exe` committed to the scanned repository could have run.
- **Custom rules under `--restricted-config` must be RE2.** They no longer fall back to Python's
  backtracking `re`, so a rule from a pull request can't hang the scan. A rule using lookarounds or
  backreferences, or a missing google-re2, stops the run (exit `2`). Untrusted rules files must be
  regular files under the working directory, with at most 200 rules of at most 1,000 characters.
  The GitHub Action now installs the `re2` extra.
- **`mask --from` verifies each detected value**, as inline masking does, and inline masking now
  checks each detection instead of each merged region, so a value inside a larger merged region
  is still caught when another copy of it is left unmasked.

### Fixed

- Configuration and custom rules files are checked for type. `"findings_only": "false"` and
  `"replace_defaults": "false"` used to turn the option on, list items were converted with
  `str()`, an explicit `null` was treated as "not set", and wrongly typed values (for example
  `"aws": {"tps_detect": "40"}`, `"rules": 5`, or a rule `"severity": 5`) crashed with exit `1`,
  which reads as "findings". All of these now exit `2` with a message. A rule `group` must be a
  whole number between 0 and the pattern's group count, and unknown keys in a rule are refused.
- `aws.max_attempts` and `aws.pool_size` must be at least 1, `aws.endpoint_url` must be `https://`,
  AWS rate limits must be finite, `validation_patterns` are compiled when the file loads, and a
  `version` other than `1` is refused.
- RE2 custom rules no longer make a file with an undecodable byte "not scanned" (google-re2 can't
  encode the placeholder for that byte); they run on a copy with the same offsets.
- `pii-scan mask --from` checks every report record and exits `2` on a malformed one instead of
  crashing, refuses unknown encodings, and refuses findings beyond the end of the file.
- An unexpected internal error exits `2`, never `1`.
- Rejected RE2 patterns no longer print a C++ log line to stderr.

### Added

- CI: tests on Linux and macOS with Python 3.11 to 3.14 and free-threaded 3.14t; an informational
  Windows job; ruff; actionlint; and runs of the action itself, including custom rules.

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
