# Detection Layers

> **Audience**: anyone deciding which detection to run and what it will cost. Prices and quotas
> below were checked against AWS documentation in September 2026; confirm them for your region
> and account before planning a large run.

- [How layers chain](#how-layers-chain)
- [The regex layer](#the-regex-layer)
- [AWS layers compared](#aws-layers-compared)
- [Choosing a combination](#choosing-a-combination)
- [Cost and throughput planning](#cost-and-throughput-planning)
- [Setting up the guardrails layer](#setting-up-the-guardrails-layer)
- [Accuracy notes](#accuracy-notes)
- [Entity types](#entity-types)

## How layers chain

`--layers` takes an ordered list. `regex` always runs on the whole file. The AWS layers run on
chunks, and each one runs only where the AWS layer before it found something:

```mermaid
graph LR
    F[File text] --> R[regex: whole file]
    F --> C{contains: any PII type?}
    C -- no --> D1[chunk done]
    C -- yes --> G{guardrails: matches?}
    G -- no --> D2[chunk done]
    G -- yes --> X[detect: exact spans and scores]
```

- A **screen** layer (`contains`) only decides whether to continue.
- A **detector** layer (`guardrails`, `detect`) produces findings. A later detector runs only on
  chunks where the earlier one found something, and all findings are combined.
- The last AWS layer must be a detector.
- If any call fails after retries, the file is reported as *not scanned*; it is never reported
  clean. Credential and permission errors stop the run.

## The regex layer

Runs locally and costs nothing. Every built-in rule is written to run in linear time, and a
rule's pattern only runs when its keyword (for example `AKIA`, `://`, or `password`) appears.

| Type | What it matches | Validation |
|------|-----------------|------------|
| `AWS_ACCESS_KEY` | `AKIA`, `ASIA`, `ABIA`, `ACCA` key IDs | Exact format |
| `AWS_SECRET_KEY` | 40-character secret after an `aws_secret_access_key` label | Label required |
| `PRIVATE_KEY` | PEM private key blocks and headers | |
| `GITHUB_TOKEN`, `SLACK_TOKEN`, `STRIPE_KEY`, `GOOGLE_API_KEY` | Provider token formats | Prefix and length |
| `JWT`, `BEARER_TOKEN` | JSON Web Tokens and `Bearer` credentials | |
| `CONNECTION_STRING` | Password in `scheme://user:password@host` URLs | |
| `PASSWORD`, `API_KEY`, `GENERIC_SECRET` | Values assigned to `password`, `api_key`, `secret`, `token` names | |
| `SSN` | `123-45-6789` and `123 45 6789` | Rejects area 000, 666, 900-999, group 00, serial 0000 |
| `CREDIT_DEBIT_NUMBER` | 13-19 digit card numbers, with spaces or dashes | Issuer prefix and Luhn checksum |
| `EMAIL` | Email addresses | Not inside URL credentials |

Add your own with [custom rules](configuration.md#custom-regex-rules).

## AWS layers compared

| | `contains` | `guardrails` | `detect` |
|---|---|---|---|
| API | Comprehend `ContainsPiiEntities` | Bedrock `ApplyGuardrail` | Comprehend `DetectPiiEntities` |
| Returns | Entity types and scores, no locations | Matched text and type, no scores | Exact character spans and scores |
| Price | $0.000002 per 100 characters | Sensitive information filter, per 1,000 text units (1 unit = 1,000 characters) | $0.0001 per 100 characters |
| Minimum charge | 300 characters per request | per text unit | 300 characters per request |
| Request size used | 90 KB | 20,000 characters | 90 KB |
| Default quota | 25 requests/s | About 25 text units/s (check Service Quotas) | 200/s us-east-1, 100/s us-west-2, 50/s elsewhere |
| pii-scan default rate | `--max-tps-contains 20` | `guardrail_chars_per_second 20000` | `--max-tps-detect 40` |
| Languages | Several; set `--language` | Per guardrail | English and Spanish |

pii-scan finds the location of each Guardrails match by searching the chunk for the matched text,
tolerating whitespace differences. Every occurrence is reported. A match that can't be found
fails the chunk, so the file is reported as not scanned.

## Choosing a combination

| Goal | `--layers` | Notes |
|------|------------|-------|
| Secrets and structured PII, no data leaves the machine | `regex` | Default. Fast and free. |
| Best accuracy for the money | `regex,contains,detect` | What `--aws` selects. Contains screens every chunk cheaply; Detect runs only on positives. |
| Lowest AWS cost for masking | `regex,contains,guardrails` | No confidence scores; Guardrails quota is the bottleneck. |
| Confirm, then locate precisely | `regex,contains,guardrails,detect` | Detect runs only where Guardrails confirmed a match. |
| Maximum recall, cost no object | `regex,detect` | Every chunk goes to Detect. |

## Cost and throughput planning

Example: 500,000 files averaging 20 KB, about 10 billion characters, with 10% of the text
escalated past the screen. List prices, before any volume discounts:

| Layers | Estimated cost |
|--------|----------------|
| `regex,detect` | about $10,000 |
| `regex,contains,detect` | about $200 (screen) + $1,000 (detect) = $1,200 |
| `regex,contains,guardrails` | about $200 + Guardrails on 1 billion characters (see pricing page) |

Throughput is set by quotas, not by pii-scan. Each chunk (a whole file, for files under 90 KB) is
one request, so the `contains` screen processes about 20 small files per second at its default
rate. For estates of this size, request quota increases for `ContainsPiiEntities` (and
`DetectPiiEntities` or Guardrails) in Service Quotas, then raise `--max-tps-*` to about 80% of
the new quota.

The run summary reports AWS calls and an estimated cost at list price. Try a representative
subset first.

## Setting up the guardrails layer

Create a guardrail with a sensitive information filter for the entity types you care about, with
**input evaluation enabled** (pii-scan sends file text as guardrail input), then pass its ID:

```bash
cat > pii.json <<'EOF'
{"piiEntitiesConfig": [
  {"type": "NAME", "action": "NONE", "inputEnabled": true, "inputAction": "NONE", "outputEnabled": false},
  {"type": "EMAIL", "action": "NONE", "inputEnabled": true, "inputAction": "NONE", "outputEnabled": false},
  {"type": "PHONE", "action": "NONE", "inputEnabled": true, "inputAction": "NONE", "outputEnabled": false},
  {"type": "ADDRESS", "action": "NONE", "inputEnabled": true, "inputAction": "NONE", "outputEnabled": false},
  {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "NONE", "inputEnabled": true, "inputAction": "NONE", "outputEnabled": false},
  {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "NONE", "inputEnabled": true, "inputAction": "NONE", "outputEnabled": false}
]}
EOF

aws bedrock create-guardrail --region us-east-1 --name pii-scan \
  --blocked-input-messaging "blocked" --blocked-outputs-messaging "blocked" \
  --sensitive-information-policy-config file://pii.json

pii-scan doctor --layers guardrails --guardrail-id <id> --region us-east-1
```

`NONE` detects without masking in the Guardrails response; pii-scan does its own masking. If input
evaluation is off, Guardrails returns "no action" for every request. pii-scan detects this (no
sensitive information units were processed) and stops with exit code `2` instead of reporting files
as clean, and `pii-scan doctor` fails unless the test email is detected.

Guardrails type names such as `US_SOCIAL_SECURITY_NUMBER` are reported under the Comprehend names
(`SSN`) so results from all layers line up.

## Accuracy notes

- `--screen-threshold` (default `0.5`) is the minimum `contains` label score that sends a chunk on.
  Lower it for higher recall; the screen is cheap, so erring low is usually right.
- `--min-confidence` (default `0.85`) filters `detect` results.
- A file with no regex hit can still contain PII (for example a name in a medical note). Use an
  AWS layer when free text matters.
- Chunks overlap by 1,024 characters, so an entity shorter than that is never split.
- Emoji and other characters outside the Basic Multilingual Plane are replaced with a single
  placeholder character before text is sent to AWS, so reported offsets line up exactly with the
  original file. `pii-scan doctor` verifies this against the live service.

## Entity types

AWS layers report these Comprehend types (restrict them with `entity_types`):

`ADDRESS AGE AWS_ACCESS_KEY AWS_SECRET_KEY BANK_ACCOUNT_NUMBER BANK_ROUTING CA_HEALTH_NUMBER
CA_SOCIAL_INSURANCE_NUMBER CREDIT_DEBIT_CVV CREDIT_DEBIT_EXPIRY CREDIT_DEBIT_NUMBER DATE_TIME
DRIVER_ID EMAIL INTERNATIONAL_BANK_ACCOUNT_NUMBER IN_AADHAAR IN_NREGA IN_PERMANENT_ACCOUNT_NUMBER
IN_VOTER_NUMBER IP_ADDRESS LICENSE_PLATE MAC_ADDRESS NAME PASSPORT_NUMBER PASSWORD PHONE PIN
SSN SWIFT_CODE UK_NATIONAL_HEALTH_SERVICE_NUMBER UK_NATIONAL_INSURANCE_NUMBER
UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER URL USERNAME US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER
VEHICLE_IDENTIFICATION_NUMBER`

`DATE_TIME`, `URL`, and `AGE` are off by default because they are noisy in most data.
