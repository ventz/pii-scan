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

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [AWS Comprehend vs Regex Scanning](#aws-comprehend-vs-regex-scanning)
- [Configuration Options](#configuration-options)
- [AWS Comprehend Entity Types](#aws-comprehend-entity-types)
- [Custom Regex Patterns](#custom-regex-patterns)
- [GitHub Action](#github-action)
- [AWS Permissions](#aws-permissions)

## Installation

### Using uv (Recommended)

```bash
uv pip install boto3
```

### Using pip

```bash
pip install boto3
```

## Usage

### Basic Usage

```bash
# Scan only git changes in current directory (default)
./pii_scan

# Scan specific file
./pii_scan path/to/file.txt

# Scan specific directory (git diff mode)
./pii_scan /path/to/directory

# Scan all files recursively in current directory
./pii_scan --all

# Scan all files in specific directory
./pii_scan --all /path/to/directory

# Show help
./pii_scan --help
```

### Command Line Options

```
Positional Arguments:
    path                    File or directory to scan (default: current directory)

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
./pii_scan --all --custom-regex custom_regex_patterns.json

# Scan git changes with higher confidence threshold
./pii_scan --min-confidence 0.9

# Output findings in JSON format
./pii_scan --output json

# Exclude additional directories
./pii_scan --exclude-dirs "build,dist,node_modules"

# Use a specific AWS region
./pii_scan --region us-west-2

# Scan specific directory with verbose output
./pii_scan --verbose /path/to/project
```

## AWS Comprehend vs Regex Scanning

This tool uses two complementary approaches for detecting sensitive information:

### AWS Comprehend (PII Detection)

**What it does:**
- Uses machine learning to detect personally identifiable information (PII)
- Understands context and natural language patterns
- Detects a wide range of entity types (names, addresses, phone numbers, etc.)

**When to use:**
- ✅ Detecting PII in natural text (emails, documents, logs)
- ✅ Finding standard PII types (SSN, credit cards, phone numbers, etc.)
- ✅ Context-aware detection (can distinguish between different uses of numbers)
- ✅ Multi-language support and country-specific formats

**Limitations:**
- ❌ May not catch custom secret formats specific to your organization
- ❌ Less effective for detecting API keys, tokens, or custom identifiers
- ❌ Requires AWS credentials and incurs API costs

### Regex Pattern Scanning

**What it does:**
- Uses regular expressions to find exact patterns in text
- Fast, deterministic pattern matching
- No external API calls required

**When to use:**
- ✅ **Detecting secrets and credentials** (passwords, API keys, tokens)
- ✅ Finding organization-specific patterns (custom IDs, internal formats)
- ✅ Exact pattern matching (e.g., `password="..."` assignments)
- ✅ When you need guaranteed detection of specific formats
- ✅ Offline scanning without AWS dependencies

**Limitations:**
- ❌ Can produce false positives with overly broad patterns
- ❌ Requires manual pattern definition for new types
- ❌ No context awareness

### Best Practice: Use Both!

The tool runs **both methods simultaneously** for comprehensive coverage:
- **AWS Comprehend** catches standard PII in natural text
- **Regex patterns** catch secrets, passwords, and custom formats

This dual approach is especially powerful for:
- Detecting hardcoded credentials (`password="secret123"`)
- Finding API keys and bearer tokens
- Catching both structured data (SSN) and unstructured PII (names in comments)

## Configuration Options

You can customize the scanner's behavior using a configuration file (JSON format). Here are all available options:

### Example `config.json`

```json
{
  "max_workers": 16,
  "max_bytes": 99000,
  "max_file_size": 10000000,
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
  ],
  "validation_patterns": {
    "AWS_ACCESS_KEY": "^AKIA[0-9A-Z]{16}$",
    "AWS_SECRET_KEY": "^[A-Za-z0-9/+=]{40}$"
  }
}
```

### Configuration Options Explained

#### Performance Settings

- **`max_workers`** (default: `8`)
  - Number of concurrent threads for file processing
  - Higher values = faster scanning but more CPU/memory usage
  - Recommended: 8-16 for most systems

- **`max_bytes`** (default: `99000`)
  - Maximum bytes per chunk sent to AWS Comprehend (AWS limit: 100KB)
  - Don't change this unless you know what you're doing

- **`max_file_size`** (default: `10000000` = 10MB)
  - Skip files larger than this size (in bytes)
  - Prevents scanning huge files that could slow down the process

- **`max_retries`** (default: `3`)
  - Number of retry attempts for AWS API throttling
  - Uses exponential backoff

- **`retry_delay`** (default: `1.0`)
  - Initial delay (in seconds) before retry
  - Doubles with each retry attempt

#### Detection Settings

- **`min_confidence_score`** (default: `0.85`, range: `0.0-1.0`)
  - Minimum confidence threshold for AWS Comprehend detections
  - Higher values = fewer false positives but may miss some findings
  - Recommended: `0.85-0.95` for production use

#### Entity Type Configuration

- **`critical_entity_types`** (array of entity types)
  - **BREAKS the CI/CD pipeline** if detected
  - Use for high-severity findings that should block deployment
  - Examples: `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `PASSWORD`, `CREDIT_CARD`
  - These findings are displayed with full context and detail

- **`security_relevant_entity_types`** (array of entity types)
  - **Flags findings but allows pipeline to continue**
  - Use for important but non-critical findings that need review
  - Includes all critical types plus additional ones like `USERNAME`, `EMAIL`, `IP_ADDRESS`
  - Only entities in this list will be reported; others are ignored

**Key Difference:**
```
critical_entity_types       → EXIT CODE 1 (CI/CD FAILS)
security_relevant_entity_types → Shows warning but EXIT CODE depends on critical types
```

#### File Filtering

- **`excluded_dirs`** (array of directory names)
  - Directories to skip during scanning
  - Default: `[".git", ".venv", "node_modules", "__pycache__"]`
  - Add any build/dependency directories

- **`excluded_extensions`** (array of file extensions)
  - File extensions to skip
  - Default: `[".min.js", ".map", ".svg", ".woff", ".ttf"]`
  - Add binary or minified file types

#### Validation Patterns

- **`validation_patterns`** (object mapping entity types to regex patterns)
  - Additional validation for detected entities
  - Reduces false positives by ensuring format matches
  - Example: Verify AWS keys match the expected format
  ```json
  {
    "AWS_ACCESS_KEY": "^AKIA[0-9A-Z]{16}$",
    "AWS_SECRET_KEY": "^[A-Za-z0-9/+=]{40}$"
  }
  ```

## AWS Comprehend Entity Types

AWS Comprehend can detect the following PII entity types. Configure which ones to scan for using `security_relevant_entity_types` and `critical_entity_types` in your config.

### Universal PII Entity Types

These are detected across all content regardless of country:

| Entity Type | Description | Example |
|-------------|-------------|---------|
| `ADDRESS` | Physical address | "100 Main Street, Anytown, USA" |
| `AGE` | Person's age | "40 years old" |
| `AWS_ACCESS_KEY` | AWS access key ID | "AKIAIOSFODNN7EXAMPLE" |
| `AWS_SECRET_KEY` | AWS secret access key | "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| `CREDIT_DEBIT_CVV` | Card CVV code | "123" (or "1234" for Amex) |
| `CREDIT_DEBIT_EXPIRY` | Card expiration | "01/25", "Jan 2025" |
| `CREDIT_DEBIT_NUMBER` | Credit/debit card number | "4111111111111111" |
| `DATE_TIME` | Date or time | "January 19, 2020", "11 am" |
| `DRIVER_ID` | Driver's license number | Alphanumeric, format varies by region |
| `EMAIL` | Email address | "user@example.com" |
| `INTERNATIONAL_BANK_ACCOUNT_NUMBER` | IBAN | Format varies by country |
| `IP_ADDRESS` | IPv4 address | "198.51.100.0" |
| `LICENSE_PLATE` | Vehicle license plate | Format varies by region |
| `MAC_ADDRESS` | Network MAC address | "00:1B:44:11:3A:B7" |
| `NAME` | Person's name | "John Doe" (excludes titles) |
| `PASSWORD` | Password string | "*very20special#pass*" |
| `PHONE` | Phone/fax/pager number | "+1-555-123-4567" |
| `PIN` | 4-digit PIN | "1234" |
| `SWIFT_CODE` | Bank SWIFT/BIC code | "AAAA BB CC DDD" (8 or 11 chars) |
| `URL` | Web address | "www.example.com" |
| `USERNAME` | Account username | Login name, screen name, handle |
| `VEHICLE_IDENTIFICATION_NUMBER` | VIN | 17-character identifier |

### Country-Specific PII Entity Types

#### Canada
| Entity Type | Description |
|-------------|-------------|
| `CA_HEALTH_NUMBER` | 10-digit health service number |
| `CA_SOCIAL_INSURANCE_NUMBER` | 9-digit SIN (e.g., "123-456-789") |

#### India
| Entity Type | Description |
|-------------|-------------|
| `IN_AADHAAR` | 12-digit Aadhaar ID |
| `IN_NREGA` | 2 letters + 14 digits |
| `IN_PERMANENT_ACCOUNT_NUMBER` | 10-character PAN |
| `IN_VOTER_NUMBER` | 3 letters + 7 digits |

#### United Kingdom
| Entity Type | Description |
|-------------|-------------|
| `UK_NATIONAL_HEALTH_SERVICE_NUMBER` | 10-digit NHS number |
| `UK_NATIONAL_INSURANCE_NUMBER` | NINO (e.g., "AA123456C") |
| `UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER` | 10-digit UTR |

#### United States
| Entity Type | Description |
|-------------|-------------|
| `BANK_ACCOUNT_NUMBER` | 10-12 digit account number |
| `BANK_ROUTING` | 9-digit routing number |
| `PASSPORT_NUMBER` | 6-9 alphanumeric characters |
| `US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER` | 9-digit ITIN starting with "9" |
| `SSN` | 9-digit Social Security Number |

### Recommended Entity Type Configurations

#### High-Security Environment (Strict)
```json
{
  "critical_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD",
    "CREDIT_DEBIT_NUMBER",
    "SSN",
    "BANK_ACCOUNT_NUMBER"
  ],
  "security_relevant_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD",
    "CREDIT_DEBIT_NUMBER",
    "CREDIT_DEBIT_CVV",
    "CREDIT_DEBIT_EXPIRY",
    "SSN",
    "BANK_ACCOUNT_NUMBER",
    "BANK_ROUTING",
    "PASSPORT_NUMBER",
    "DRIVER_ID",
    "EMAIL",
    "PHONE",
    "USERNAME",
    "IP_ADDRESS"
  ]
}
```

#### Development Environment (Balanced)
```json
{
  "critical_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD"
  ],
  "security_relevant_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD",
    "CREDIT_DEBIT_NUMBER",
    "SSN",
    "EMAIL",
    "PHONE"
  ]
}
```

#### Secrets-Only (Minimal)
```json
{
  "critical_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD"
  ],
  "security_relevant_entity_types": [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PASSWORD"
  ]
}
```

## Custom Regex Patterns

Define custom regex patterns in a JSON file for organization-specific detection needs.

### Example `custom_regex_patterns.json`

```json
{
  "Social Security Number": "\\b(?!000|666|9\\d{2})([0-8]\\d{2}|7([0-6]\\d|7[012]))([-]?)(?!00)\\d\\d\\3(?!0000)\\d{4}\\b",
  "Credit Card Number": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b",
  "Generic API Key": "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]([^'\"]{10,})['\"]",
  "Database Connection String": "(?i)(jdbc|mongodb|postgresql|mysql|sqlserver):[^\\s]+",
  "Private Key Header": "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
  "JWT Token": "eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*",
  "Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
  "GitHub Token": "ghp_[0-9a-zA-Z]{36}",
  "Generic Secret Assignment": "(?i)(secret|token|key)\\s*[:=]\\s*['\"]([^'\"]{8,})['\"]"
}
```

### Best Practices for Regex Patterns

1. **Be Specific**: Avoid overly broad patterns that catch too much
2. **Use Anchors**: Use `\b` word boundaries to prevent partial matches
3. **Test Thoroughly**: Verify patterns with test data before deploying
4. **Case Insensitive**: Use `(?i)` flag for flexibility
5. **Escape Special Chars**: Remember to escape backslashes in JSON (`\\` not `\`)

## GitHub Action

This tool can be used as a GitHub Action to scan code changes in pull requests.

### Example Workflow

```yaml
name: Scan for PII and Secrets

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  pii-scan:
    name: Scan for PII and Secrets
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3
      with:
        fetch-depth: 0  # Required for git diff

    - name: Run PII Scanner
      uses: harvard-ea/action-pii-scanning-using-aws@main
      with:
        custom-regex-file: custom_regex_patterns.json
        min-confidence: '0.85'
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        AWS_DEFAULT_REGION: 'us-east-1'
```

## AWS Permissions

### Required IAM Permissions

The tool requires AWS credentials with the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "comprehend:DetectPiiEntities"
      ],
      "Resource": "*"
    }
  ]
}
```

### Setting Up AWS Credentials

#### Option 1: AWS CLI (Recommended)
```bash
aws configure
```

#### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### Option 3: IAM Role (for EC2/ECS)
If running on AWS infrastructure, attach an IAM role with the required permissions.

### AWS Costs

AWS Comprehend charges per unit (100 characters = 1 unit):
- Standard: ~$0.0001 per unit
- PII detection may incur slightly higher costs
- See [AWS Comprehend Pricing](https://aws.amazon.com/comprehend/pricing/) for current rates

**Cost Example:**
- Scanning 1MB of code ≈ 10,000 units ≈ $1.00
- Most scans cost a few cents

## Motivation

The aim was to build a free, open-source, drop-in alternative to Nightfall, which is both overpriced and limited in functionality.

## Bugs, Improvements, or Questions?

Please open an [Issue](https://github.com/ventz/pii-scan/issues) — contributions via PRs are also welcome!

## License

This project is licensed under the MIT License.

© Ventz Petkov
