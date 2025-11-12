# Security Dashboard

This project provides a Python-based security dashboard that consolidates findings from
[AWS Security Hub](https://aws.amazon.com/security-hub/) and
[GitHub Advanced Security](https://docs.github.com/en/code-security) (GHAS). The
command-line interface can pull live data from both services or operate using bundled
sample findings, making it easy to demo without credentials.

## Features

- Query AWS Security Hub for security findings with optional severity filtering.
- Retrieve GitHub Code Scanning, Secret Scanning, and Dependabot alerts.
- Normalise data into a single schema and generate aggregate metrics by provider and
  severity.
- Render a console table or export the raw findings as JSON for further processing.

## Getting Started

### Prerequisites

- Python 3.10+
- AWS credentials with access to Security Hub findings.
- Optional GitHub personal access token with permissions to view GHAS alerts.

Install dependencies using `pip`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Usage

Show a demo using the bundled sample data:

```bash
security-dashboard --sample-data
```

Query live services (environment variables are recommended for configuration):

```bash
export AWS_REGION="us-east-1"
export AWS_PROFILE="security-auditor"
export GITHUB_TOKEN="<github-token>"
export GITHUB_OWNER="example-org"
export GITHUB_REPO="example-repo"
security-dashboard --include-github \
  --include-code-scanning \
  --include-secret-scanning \
  --include-dependabot
```

The CLI also supports exporting data in JSON form:

```bash
security-dashboard --sample-data --output-json
```

### Running Tests

```bash
pytest
```

## Project Structure

```
security_dashboard/
├── aws_security_hub.py      # AWS Security Hub integration helpers
├── cli.py                   # Command-line interface implementation
├── config.py                # Environment-driven configuration
├── dashboard.py             # Aggregation logic for reports
├── github.py                # GitHub Advanced Security integration helpers
├── models.py                # Shared domain models
examples/
└── sample_findings.json     # Sample findings used for demo mode
```

## Notes

- Network calls to AWS or GitHub are only made when the corresponding CLI flags are
  enabled and credentials are available.
- The sample data can be extended or replaced to reflect your organisation's context.
- This repository starts life locally. To publish it to your own GitHub account:
  1. Create a new empty repository on GitHub (do not initialise it with a README or
     `.gitignore`).
  2. Add it as a remote in this project directory:

     ```bash
     git remote add origin git@github.com:<your-account>/<your-repo>.git
     ```

  3. Push the existing history:

     ```bash
     git push -u origin main
     ```

  After the push finishes, the project will appear on your GitHub page and future
  commits can be published with `git push`.
