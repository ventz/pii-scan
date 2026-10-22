# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/ventz/pii-scan/security/advisories/new).
Do not open a public issue, and do not include real personal data in reports.

You can expect an acknowledgment within a few business days.

## How pii-scan handles sensitive data

pii-scan reads data that is sensitive by definition. These are the guarantees it is built
around; a violation of any of them is a security bug.

- **Values stay out of output.** Console output, reports (text, JSON, JSONL, CSV, SARIF),
  GitHub annotations, the job summary, the cache, and baselines contain typed placeholders and
  keyed fingerprints, never matched values. `--show-values` is the only exception; it is refused
  in CI and never uses the cache.
- **Fail closed.** A file that was not fully analyzed is never reported clean and never written
  to a masked output tree.
- **Reports are private.** Files written with `--report` and masked copies are created with mode
  `0600`; directories created for masked output use `0700`.
- **Masking is non-destructive.** Masked copies go to a separate directory that must not overlap
  the scanned tree. Writes are atomic and never follow a symlink. Originals are never modified.
- **Untrusted files are handled defensively.** Symlinks, FIFOs, sockets, and devices are skipped
  without being opened; reads are bounded by `max_file_size`, and each opened file is verified to
  still be under the scan root (so a parent directory swapped for a symlink mid-scan is refused).
  Built-in regex rules avoid catastrophic backtracking. A file where one rule exceeds the match cap
  is reported as not scanned rather than partially reported or masked.
- **Git is invoked defensively.** `core.fsmonitor`, hooks, and external diff drivers are disabled,
  git runs only in changed-files mode, and repositories whose own git config (`.git/config` or a
  worktree's `config.worktree`) sets filters, includes, or diff commands are refused unless
  `--trust-repo` is given. Submodules are never examined, so their own config can't run anything;
  git never fetches or uses any transport, so a partial clone can't trigger a download; and git
  is run by absolute path from `PATH`, never from the scanned directory.
- **Untrusted configuration can't loosen policy.** With `--restricted-config` (always on in the
  GitHub Action), a configuration or custom rules file from the scanned tree can only add rules or
  raise severities, and custom rules must compile as linear-time RE2 and live under the working
  directory.
- **Spending is bounded on request.** `--aws-max-chars` stops the run once a character budget has
  been sent to AWS.
- **AWS endpoints are pinned.** `AWS_ENDPOINT_URL*` environment variables are ignored unless an
  endpoint is set explicitly in configuration, so a planted environment cannot redirect scanned
  content. Credentials come from the standard AWS credential chain; pii-scan never stores them.

## Data sent to AWS

The regex layer runs locally and sends nothing anywhere. The `contains`, `detect`, and
`guardrails` layers send file text to Amazon Comprehend or Amazon Bedrock in the region you
choose. Before enabling them:

- Confirm that sending the data to AWS is allowed by your data-handling policy.
- Review the [Amazon Comprehend FAQ](https://aws.amazon.com/comprehend/faqs/) on how inputs may be
  used, and consider an AWS Organizations
  [AI services opt-out policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html).
- Pin a region deliberately (`--region` or `aws.region`) and, if required, use a VPC interface
  endpoint (`aws.endpoint_url`).
- Grant the scanning role only the actions it needs (see
  [docs/github-action.md](docs/github-action.md#aws-permissions)).

## Scope

In scope: this repository's code, the GitHub Action, and default configuration. Out of scope:
detection accuracy of AWS services, and findings that require an attacker to already control
the pii-scan configuration file or command line.
