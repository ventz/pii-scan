# Scanning File Shares

> **Audience**: operators scanning large estates such as SMB or NFS shares, archives, or exported
> drives with hundreds of thousands of files.

- [Before you start](#before-you-start)
- [A production-style run](#a-production-style-run)
- [Throughput](#throughput)
- [Interrupting and resuming](#interrupting-and-resuming)
- [Reading the results](#reading-the-results)
- [Using AWS layers at scale](#using-aws-layers-at-scale)
- [Checklist](#checklist)

## Before you start

- **Mount read-only.** pii-scan never writes to scanned paths, but a read-only mount makes that
  impossible by construction.
- **Run close to the data.** Each file is listed, opened, and read once; latency per file
  dominates on network storage.
- **Keep state on local disk.** Put the report, cache, and masked output on local storage, never
  on the share being scanned. The output directory must not overlap the scanned paths.
- **Start regex-only.** It is free and sends nothing anywhere. Add AWS layers after you have seen
  the regex results and estimated cost ([Detection Layers](detection-layers.md)).

## Windows

pii-scan applies the same protections on Windows as on Linux and macOS, through Windows' own
mechanisms:

- **Links.** Symlinks, junctions, and other name-surrogate reparse points are skipped (`symlink`),
  and each opened file is checked to still be under the scan root, so a folder swapped for a
  junction mid-scan is refused (`outside_root`). Deduplicated files on Windows Server are reparse
  points too, but they hold real data and are read normally.
- **Cloud placeholders.** OneDrive "online-only" files and folders, and other offline or
  recall-on-access files, are reported as not scanned (`offline_placeholder`) instead of being
  downloaded during the scan. The same applies to iCloud Drive placeholders on macOS.
- **Private output.** Reports, the cache, baselines, and masked copies get an ACL that grants
  access only to the current user and SYSTEM, with nothing inherited from the parent folder (the
  equivalent of modes 0600 and 0700).
- **Names Windows can't store.** A masked copy whose name contains `:` (which would create an
  alternate data stream), is a device name such as `CON` or `NUL`, or ends in a dot or space is
  not written (`mask_failed`), since it would land somewhere else. This matters when masking a
  share created on Linux or macOS.
- **Exact names.** Files are opened by their exact name, so `report.` and `report` are different
  files and a file called `NUL` is read as a file, as they are on the server.
- **Resume cache.** With `--cache`, a file's NTFS change time is read too (Windows' `st_ctime` is
  its creation time), so an edit with the old modification time restored is still rescanned.
- **DFS and mounted volumes.** Files behind a DFS link that points to another server may
  resolve outside the scan root and be reported as `outside_root`; scan the target share
  directly instead. A volume mounted into a folder uses the same kind of reparse point as a
  junction, so that folder is skipped (`symlink`); scan the volume by its own drive letter or
  path.
- **Coverage limits.** Alternate data streams are not scanned (only a file's main stream is).

## A production-style run

```bash
pii-scan --all \
  --workers 48 \
  --same-filesystem \
  --exclude 'Archive/Old Backups/**' \
  --output jsonl --report ~/pii-scan/finance.jsonl \
  --cache ~/pii-scan/cache.sqlite \
  --fail-on never \
  /mnt/shares/finance /mnt/shares/hr
```

- `--workers 48` raises parallel reads; see [Throughput](#throughput).
- `--same-filesystem` stops the walk from wandering into other mounts under the share.
- `--exclude` takes root-relative globs; snapshot and recycle-bin folders are skipped by
  [default](configuration.md#default-excludes).
- `--output jsonl --report` streams one record per file to disk, so memory stays flat.
- `--cache` makes re-runs skip unchanged files.
- `--fail-on never` suits audits, where the report is the product rather than the exit code.

## Throughput

Reference numbers for regex-only scanning, 20,000 files (108 MB, 5.4 KB average) on a local SSD,
Apple M3:

| Workers | Files per second | Peak memory |
|---------|------------------|-------------|
| 1 | about 3,800 | about 31 MB |
| 16 | about 4,300 | about 32 MB |

On local disks the CPU is the limit, so more workers add little. On network shares the limit is
per-file latency, and more workers help until the file server pushes back:

- Start with `--workers 32` for SMB or NFS and increase while files per second keeps rising.
- Watch the progress lines on stderr (every 30 seconds when not on a terminal).
- Memory does not grow with the number of files; it grows slightly with `--workers` and file size
  (up to `--max-file-size` per file in flight).

## Interrupting and resuming

Press `Ctrl-C` once. pii-scan stops taking new files, finishes writing, prints the summary, and
exits `130`. Every line already written to a JSONL report is complete.

Run the same command again with the same `--cache` file: files whose path, size, and modification
time are unchanged (and whose results were computed with the same settings) are taken from the
cache. Changing layers, rules, thresholds, or entity types invalidates cached results.
Masking runs (`--mask-out`) always rescan.

## Reading the results

The summary on stderr tells you how complete the run was:

```text
INCOMPLETE: 212 files could not be scanned; no blocking findings in the rest.
Files: 481,904 scanned (0 from cache), 3,112 with findings, 212 not scanned, 91,550 skipped.
Not scanned: open_failed 180, too_large 29, undecodable 3
Skipped: binary 88,120, symlink 2,901, extension 529
```

- **Not scanned** files need attention: permissions (`open_failed`), size (`too_large`, raise
  `--max-file-size`), encoding (`undecodable`), one rule matching more than
  `max_matches_per_rule` times (`match_limit`, raise it in the configuration), or a path that
  resolved outside the scan root (`outside_root`, investigate), or a cloud placeholder whose data
  isn't on the machine (`offline_placeholder`; make the files available offline first, for example
  OneDrive's "Always keep on this device" or `brctl download` for iCloud Drive). The first
  examples are listed; the JSONL report has every one (`"status": "not_scanned"`).
- **Skipped** files were excluded on purpose. `binary` includes PDF and Office documents, which
  are not extracted yet ([roadmap](architecture.md#roadmap)).

Useful queries on a JSONL report with [jq](https://jqlang.org/):

```bash
# files with critical findings
jq -r 'select(.kind=="finding" and .severity=="critical") | .relpath' finance.jsonl | sort -u

# findings per type
jq -r 'select(.kind=="finding") | .type' finance.jsonl | sort | uniq -c | sort -rn

# everything that could not be scanned, with reasons
jq -r 'select(.kind=="file" and .status=="not_scanned") | "\(.reason)\t\(.path)"' finance.jsonl
```

## Using AWS layers at scale

- **Screen first.** `--layers regex,contains,detect` keeps the expensive call for the chunks that
  need it.
- **Quotas set the pace.** At the default rate the `contains` screen handles about 20 small files
  per second, which is too slow for hundreds of thousands of files. Request quota increases in
  Service Quotas, then set `--max-tps-contains` and `--max-tps-detect` to about 80% of the new
  limits.
- **Check the estimate.** The summary prints AWS calls, characters sent, and an estimated cost;
  scan one representative folder first and extrapolate.
- **Set a ceiling.** `--aws-max-chars` stops the run once that many characters have been sent, so
  a share full of unexpectedly large or PII-dense files can't run up the bill. Resume with the cache.
- **Credentials.** Long runs need credentials that outlast the run (an instance role, or a role
  session longer than the expected duration). If credentials expire mid-run, pii-scan stops with
  exit code `2`; resume with the cache.

## Checklist

- [ ] Share mounted read-only; report, cache, and output on local disk
- [ ] `pii-scan doctor` passes (if using AWS layers)
- [ ] Excludes reviewed on a small folder first
- [ ] `--workers` tuned by watching files per second
- [ ] Summary shows zero or understood *not scanned* reasons
- [ ] Reports stored with the same protection as the data itself
