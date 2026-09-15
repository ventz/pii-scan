# Getting Started

> **Audience**: first-time users. By the end you will have run a local scan, read the results,
> and (optionally) enabled AWS detection layers.

## 1. Install

With [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv tool install git+https://github.com/ventz/pii-scan
pii-scan --version
```

Alternatives:

```bash
# pip into an existing environment (Python 3.11+)
pip install git+https://github.com/ventz/pii-scan

# run from a checkout without installing
git clone https://github.com/ventz/pii-scan && cd pii-scan
uv sync
uv run pii-scan --version        # or ./pii_scan --version
```

## 2. Run a first scan

The repository ships `sample_testing_data.txt`, which contains only synthetic values.

```bash
pii-scan --all sample_testing_data.txt
```

Findings go to stdout, one per line:

```text
sample_testing_data.txt:12:6: CRITICAL SSN (regex 1.00): [SSN, 11 chars]
```

That line reads: file, line 12, column 6, severity `CRITICAL`, entity type `SSN`, found by the
`regex` layer with score `1.00`. The last part is a placeholder; the value itself is never printed.

The summary goes to stderr:

```text
FAILED: 11 findings at or above high severity.
Files: 1 scanned (0 from cache), 1 with findings, 0 not scanned, 0 skipped.
```

The exit code is `1` because findings reached the default `--fail-on high` threshold. See the
[exit codes](../README.md#usage).

## 3. Choose what to scan

| You want to scan | Command |
|------------------|---------|
| Files changed on your branch (default) | `pii-scan` |
| A whole directory tree | `pii-scan --all /path` |
| Several trees in one run | `pii-scan --all /mnt/a /mnt/b` |
| Changes against a specific ref | `pii-scan --base origin/release` |

Changed-files mode compares against the merge base with origin's default branch and includes
uncommitted and untracked files. Outside a git checkout, use `--all`.

## 4. Save a report

```bash
pii-scan --all ./data --output jsonl --report findings.jsonl
```

Reports are written with owner-only permissions. Formats are described in the
[Configuration Reference](configuration.md#output).

## 5. Optional: enable AWS layers

The regex layer finds structured data (numbers with validators, keys, tokens, assignments). Names,
addresses, and free-text PII need the AWS layers. They send file text to AWS, so read
[Data sent to AWS](../SECURITY.md#data-sent-to-aws) first.

1. Configure credentials the usual way (`aws configure`, `aws sso login`, `AWS_PROFILE`, or an
   instance or CI role).
2. Grant the permissions in [AWS permissions](github-action.md#aws-permissions).
3. Verify the setup:

   ```bash
   pii-scan doctor --layers contains,detect --region us-east-1
   ```

4. Scan with a cheap screen followed by exact detection:

   ```bash
   pii-scan --all --aws --region us-east-1 ./data
   ```

The summary includes the number of AWS calls and an estimated cost. See
[Detection Layers](detection-layers.md) to choose a combination.

## Next steps

- [Masking](masking.md): write sanitized copies.
- [Scanning File Shares](scanning-shares.md): tune for hundreds of thousands of files.
- [GitHub Action](github-action.md): block pull requests that add sensitive data.
