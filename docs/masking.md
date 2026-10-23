# Masking

> **Audience**: anyone producing sanitized copies of data. Masking always writes new files; it
> never modifies the originals.

- [Mask while scanning](#mask-while-scanning)
- [Review first, then mask](#review-first-then-mask)
- [Styles](#styles)
- [Consistent pseudonyms](#consistent-pseudonyms)
- [Guarantees](#guarantees)
- [Limitations](#limitations)

## Mask while scanning

```bash
pii-scan --all --mask-out /secure/masked /mnt/share/finance
```

The output directory mirrors the scanned tree (`/mnt/share/finance/hr/a.txt` becomes
`/secure/masked/hr/a.txt`). With several scan paths, each gets its own numbered top-level folder.
Files without findings are copied unchanged so the output is a complete sanitized tree; add
`--mask-findings-only` to write only files that had findings.

All detected values are masked, including findings below `--fail-on` and findings suppressed by a
baseline.

## Review first, then mask

Save a JSONL report, review it, then apply it. Re-masking with a different style costs nothing
extra, even if the scan used AWS layers.

```bash
pii-scan --all --layers regex,contains,detect --output jsonl --report findings.jsonl /mnt/share
# review findings.jsonl (it holds locations and placeholders, not values)
pii-scan mask --from findings.jsonl --out /secure/masked --style partial
```

`pii-scan mask` checks each file's SHA-256 against the report. If a file changed since the scan,
it is not written and the command exits `3`. It also re-runs the built-in regex rules (and any
`--custom-regex` rules) on every file, so a report with deleted finding lines can't leave those
values unmasked. Findings that a baseline suppressed are in the report and are masked too.

## Styles

Using `SSN 123-45-6789` as the input:

| Style | Output | Use when |
|-------|--------|----------|
| `label` (default) | `SSN [SSN]` | Readable documents; the type stays visible |
| `generic` | `SSN [REDACTED]` | The type itself is sensitive |
| `stars` | `SSN ***********` | Fixed-width formats; length and line numbers must not change |
| `partial` | `SSN *******6789` | People need the last four characters to recognize a record |
| `hash` | `SSN [SSN:3f9a1c0b27d4]` | The same value must map to the same token everywhere (joins, analytics) |

`stars` and `partial` keep line breaks inside masked values, so line numbers in the copy match the
original.

## Consistent pseudonyms

The `hash` style uses an HMAC-SHA-256 of the value. Without a key, pii-scan generates a random key
per run: tokens are consistent within the run but not across runs. To keep tokens stable across
runs and machines, set a secret key:

```bash
export PII_SCAN_HMAC_KEY='a long random secret from your secret manager'
pii-scan --all --mask-out /secure/masked --mask-style hash /mnt/share
```

Anyone with the key can test whether a guessed value produced a token, so protect it like a
password; it must be at least 16 bytes. Tokens are 12 hex characters (48 bits), so collisions are
rare but possible across very large estates: treat them as pseudonyms, not unique identifiers.

## Guarantees

- **Fully analyzed files only.** A file that was not scanned (read error, AWS failure, too large,
  undecodable) is never written to the output tree. It is listed in the summary and the run
  exits `3`.
- **Overlaps are merged first.** Overlapping findings (for example a regex hit inside a NAME) are
  combined into one region, labeled with the most severe type, before any replacement.
- **Verification.** After masking, inline or with `mask --from`, pii-scan checks that no masked
  value of six or more characters is still present in the file. If one is, the file is not written.
- **Byte-exact everywhere else.** Encoding (UTF-8 with or without BOM, UTF-16 with or without
  BOM, UTF-32 with BOM, Windows-1252) and line endings are preserved outside the masked regions.
  Undecodable bytes in UTF-8 and Windows-1252 files survive unchanged; invalid sequences in UTF-16
  and UTF-32 files are replaced.
- **Safe writes.** The output directory must not overlap the scanned paths. Files are written
  atomically through a temporary file, with mode `0600` (directories `0700`; on Windows an ACL for
  the current user and SYSTEM only), and never through a symlink or junction. On Windows, a name
  that can't be stored safely (containing `:`, a device name such as `CON`, or a trailing dot or
  space) is reported as `mask_failed` instead of being written somewhere else.

## Limitations

- **Text files only.** Binary formats (PDF, Office documents, images) are skipped and not copied.
  Extraction for Office and PDF files is on the [roadmap](architecture.md#roadmap).
- **No in-place masking.** Replace originals yourself after reviewing the masked tree.
- **Detection bounds masking.** Masking can only remove what a layer detected. For free-text PII
  such as names, enable an AWS layer.
