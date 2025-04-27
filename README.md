# pii-scan - a PII Scanner using AWS Comprehend

A lightweight, highly configurable tool for scanning files for personally identifiable information (PII) and other sensitive data. It uses AWS Comprehend and custom regex patterns, supports fast multi-threaded execution, and can run as a standalone tool or as a GitHub Action.

## Features

- **AWS Comprehend Integration**: Leverages AWS's powerful NLP capabilities to detect PII entities
- **Custom Regex Patterns**: Add your own regex patterns to detect organization-specific sensitive data
- **Git Integration**: Scan only files that have changed in a git repository
- **Multiple Output Formats**: Output findings in text, JSON, or CSV format
- **Configurable**: Adjust confidence thresholds, excluded directories, and more
- **Multithreaded**: Process files in parallel for faster scanning
- **GitHub Action Support**: Use as a GitHub Action to scan code changes in PRs

## Installation

```bash
pip install boto3
```

## Usage

### Basic Usage

```bash
# Scan only git changes (default)
pii_scan

# Scan all files recursively
pii_scan --all

# Show help
pii_scan --help
```

### Command Line Options

```
Options:
    --all                   Scan all files recursively (default: only scan git changes)
    --help, -h              Show this help message and exit
    --config FILE           Path to configuration file
    --min-confidence FLOAT  Minimum confidence score (0.0-1.0) for PII detection
    --output FORMAT         Output format: text, json, or csv (default: text)
    --custom-regex FILE     Path to file containing custom regex patterns
    --exclude-dirs DIRS     Comma-separated list of directories to exclude
    --exclude-exts EXTS     Comma-separated list of file extensions to exclude
    --workers INT           Number of worker threads (default: 8)
    --verbose, -v           Enable verbose output
    --quiet, -q             Suppress all output except findings and errors
    --region REGION         AWS region to use for Comprehend API
```

### Examples

```bash
# Scan all files with custom regex patterns
pii_scan --all --custom-regex custom_regex_patterns.json

# Scan git changes with higher confidence threshold
pii_scan --min-confidence 0.9

# Output findings in JSON format
pii_scan --output json

# Exclude additional directories
pii_scan --exclude-dirs "build,dist,node_modules"

# Use a specific AWS region
pii_scan --region us-west-2
```

## Custom Regex Patterns

You can define custom regex patterns in a JSON file and provide it using the `--custom-regex` option. The file should contain a JSON object where keys are pattern names and values are regex patterns.

Example `custom_regex_patterns.json`:

```json
{
  "Social Security Number": "\\b(?!000|666|9\\d{2})([0-8]\\d{2}|7([0-6]\\d|7[012]))([-]?)(?!00)\\d\\d\\3(?!0000)\\d{4}\\b",
  "Credit Card Number": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\\d{3})\\d{11})\\b",
  "Harvard ID": "\\b\\d{8}\\b",
  "API Key Pattern": "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]([^'\"]{10,})['\"]",
  "Database Connection String": "(?i)(jdbc|mongodb|postgresql|mysql|sqlserver):[^\\s]+"
}
```

## Configuration File

You can provide a configuration file using the `--config` option. The file should contain a JSON object with configuration parameters.

Example `config.json`:

```json
{
  "max_workers": 8,
  "min_confidence_score": 0.9,
  "excluded_dirs": [".git", ".venv", "node_modules", "__pycache__", "dist", "build"],
  "excluded_extensions": [".min.js", ".map", ".svg", ".woff", ".ttf", ".png", ".jpg"],
  "critical_entity_types": ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PASSWORD", "CREDIT_CARD"],
  "security_relevant_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD",
    "USERNAME",
    "IP_ADDRESS",
    "EMAIL",
    "CREDIT_CARD",
    "PHONE_NUMBER"
  ]
}
```

## GitHub Action

This tool can be used as a GitHub Action to scan code changes in pull requests. See the `action.yml` file for details.

Example workflow:

```yaml
name: Scan for PII

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  pii-scan:
    name: Scan for PII
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      with:
        fetch-depth: 0

    - name: Run PII Scanner
      uses: harvard-ea/action-pii-scanning-using-aws@main
      with:
        custom-regex-file: pii-engine/custom_regex_patterns.json
        min-confidence: '0.85'
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## AWS Permissions

The tool requires AWS credentials with permissions to use the Comprehend service. You can provide these credentials using environment variables or AWS configuration files.

Required permissions:
- `comprehend:DetectPiiEntities`

## Motivation

The aim was to build a free, open-source, drop-in alternative to Nightfall, which is both overpriced and limited in functionality.

## Bugs, Improvements, or Questions?

Please open an [Issue](https://github.com/ventz/pii-scan/issues) — contributions via PRs are also welcome!

## License

This project is licensed under the MIT License.

© Ventz Petkov
