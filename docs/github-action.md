# GitHub Action

> **Audience**: maintainers who want pull requests checked for personal data and secrets.

- [Basic workflow](#basic-workflow)
- [Code scanning (SARIF)](#code-scanning-sarif)
- [AWS layers with OIDC](#aws-layers-with-oidc)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [AWS permissions](#aws-permissions)
- [Notes](#notes)

## Basic workflow

Regex-only scanning of the files a pull request or push changes. No credentials needed.

```yaml
name: pii-scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  pii-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0 # the diff base must be available
      - uses: ventz/pii-scan@v1.1.0
        with:
          fail-on: high
```

Findings appear as annotations on the changed lines and in the job summary. The job fails when a
finding reaches `fail-on`, or when files could not be scanned (unless `allow-incomplete: true`).

## Code scanning (SARIF)

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0
  - uses: ventz/pii-scan@v1.1.0
    with:
      upload-sarif: true
```

Code scanning on private repositories requires GitHub Code Security. SARIF uploads are limited to
25,000 results per run; pii-scan caps its output at that limit.

## AWS layers with OIDC

Use short-lived credentials from an IAM role instead of stored access keys. The action reads
credentials from the job environment, so configure them in a step before it.

```yaml
permissions:
  contents: read
  id-token: write

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 0
  - uses: aws-actions/configure-aws-credentials@v6
    with:
      role-to-assume: arn:aws:iam::123456789012:role/pii-scan-github
      aws-region: us-east-1
  - uses: ventz/pii-scan@v1.1.0
    with:
      layers: regex,contains,detect
      aws-region: us-east-1
```

Workflows triggered by pull requests from forks cannot request OIDC tokens. Keep a regex-only job
for those, or run AWS layers only on `push`.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `paths` | `.` | Path to scan, relative to the workspace |
| `scan-all` | `false` | Scan every file instead of only changed files |
| `base` | event base | Git ref or SHA to diff against. Defaults to the pull request base SHA, or `github.event.before` on push |
| `layers` | `regex` | `regex`, `contains`, `guardrails`, `detect` ([Detection Layers](detection-layers.md)) |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `any`, or `never` |
| `min-confidence` | | Minimum score for AWS detections |
| `output-format` | `sarif` | `sarif`, `jsonl`, `json`, `csv`, or `text` |
| `report-path` | `pii-scan-report.sarif` | Report file |
| `upload-sarif` | `false` | Upload the report to code scanning (needs `security-events: write`) |
| `custom-regex-file` | | Custom rules file |
| `config-file` | | Configuration file |
| `exclude-dirs` | | Comma-separated directory names to skip |
| `exclude-exts` | | Comma-separated suffixes to skip |
| `workers` | | File worker threads |
| `aws-region` | | Region for AWS layers |
| `guardrail-id` | | Bedrock guardrail for the `guardrails` layer |
| `allow-incomplete` | `false` | Pass even if some files could not be scanned |
| `verbose`, `quiet` | `false` | Log detail |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | `0` passed, `1` findings, `2` configuration error, `3` incomplete |
| `report-path` | Path of the report file, for example to upload with `actions/upload-artifact` |

Reports contain file locations and placeholders, never matched values.

## AWS permissions

Policy for the scanning role (drop the actions for layers you don't use):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComprehendPii",
      "Effect": "Allow",
      "Action": ["comprehend:ContainsPiiEntities", "comprehend:DetectPiiEntities"],
      "Resource": "*"
    },
    {
      "Sid": "BedrockGuardrail",
      "Effect": "Allow",
      "Action": "bedrock:ApplyGuardrail",
      "Resource": "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123example"
    }
  ]
}
```

Trust policy for GitHub OIDC, limited to one repository:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
        "StringLike": { "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*" }
      }
    }
  ]
}
```

## Notes

- **Pin the action.** Use a release tag (`@v1.1.0`) or, for the strongest guarantee, a full commit SHA.
- **Policy lives in the workflow.** A pull request can edit files in its own tree, including a
  configuration file passed with `config-file`. Keep `fail-on` and `layers` as workflow inputs so
  a pull request can't loosen them.
- **Inputs are data.** The action passes inputs to pii-scan through environment variables and a
  bash array, never through `eval`, and validates booleans and numbers.
- **Runtime.** The action installs [uv](https://docs.astral.sh/uv/) with a pinned
  `astral-sh/setup-uv` and runs pii-scan from the action's own lockfile (`uv run --locked`).
