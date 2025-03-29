# Palo Alto Networks SCM CICD Pipeline

A Python-based CICD pipeline for managing security rules in Palo Alto Networks Strata Cloud Manager (SCM).

## Overview

This project provides tools for automating the management of security rules in SCM within a CICD pipeline. It leverages the pan-scm-sdk to interact with the SCM API and provides a robust CLI interface for managing security rules.

## Project Structure

```
pan-scm-cicd/
├── .github/
│   └── workflows/            # GitHub Actions workflows
│       └── security-rules.yml
├── config/
│   └── security-rules/       # Place your security rule definitions here (YAML format)
├── examples/                 # Example configuration files
│   └── security_rules.yaml
├── src/
│   └── scm_cicd/
│       ├── __init__.py       # Package initialization
│       ├── config.py         # Dynaconf configuration
│       ├── security_rules.py # Security rules manager
│       └── cli.py            # Command-line interface
├── tests/                    # Test files
├── .secrets.yaml             # Local secrets (not version controlled)
├── pyproject.toml            # Poetry configuration
├── settings.yaml             # Configuration settings
└── README.md                 # This file
```

## Prerequisites

- Python 3.12+
- [Poetry](https://python-poetry.org/docs/#installation) for dependency management

## Installation

1. Clone the repository:

```bash
git clone https://github.com/cdot65/pan-scm-cicd.git
cd pan-scm-cicd
```

2. Install dependencies using Poetry:

```bash
poetry install
```

3. Configure your SCM credentials:

Edit the `.secrets.yaml` file with your SCM credentials:

```yaml
default:
  # This file should never be committed to version control
  # Add this file to your .gitignore

development:
  # Fill in your local development credentials
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  tsg_id: "your-tsg-id"
```

> **Important:** Add `.secrets.yaml` to your `.gitignore` file to prevent accidentally committing your credentials.

## Usage

The project provides a command-line interface for managing security rules.

### Defining Security Rules

Create security rule definitions in YAML format and place them in the `config/security-rules/` directory. See the `examples/security_rules.yaml` for reference:

```yaml
# Allow internal to internet web traffic
- name: "allow-internal-web"
  folder: "Global"
  description: "Allow internal users to access web applications"
  from_: ["trust"]
  to_: ["untrust"]
  source: ["internal-subnet"]
  destination: ["any"]
  application: ["web-browsing", "ssl", "dns"]
  service: ["application-default"]
  action: "allow"
  log_end: true
  tag: ["policy-type:allow", "service:web"]
```

### CLI Commands

#### Apply Security Rules

Apply security rules from a configuration file:

```bash
# Check syntax without applying changes
poetry run python -m scm_cicd.cli apply config/security-rules/example.yaml --dry-run

# Apply rules without committing changes
poetry run python -m scm_cicd.cli apply config/security-rules/example.yaml

# Apply rules and commit changes
poetry run python -m scm_cicd.cli apply config/security-rules/example.yaml --commit
```

#### List Security Rules

List security rules in a container:

```bash
poetry run python -m scm_cicd.cli list "Global"
```

#### Delete a Security Rule

Delete a security rule:

```bash
poetry run python -m scm_cicd.cli delete "rule-name" "Global" --commit
```

#### Commit Changes

Commit changes to SCM:

```bash
poetry run python -m scm_cicd.cli commit "Global" --message "Updated security rules"
```

## GitHub Actions CICD Integration

This project includes GitHub Actions workflows for automating security rule deployment:

1. **Validation**: All rule files are checked with Checkov and validated with dry-run mode before applying.
2. **Security Scanning**: Automatically scans for secrets and security issues.
3. **Deployment**: When pushed to main or triggered manually, rules are applied with automatic commits.

## Development

### Prerequisites

- Python 3.12+
- [Poetry](https://python-poetry.org/)
- [Gitleaks](https://github.com/zricethezav/gitleaks) (optional, for additional secrets scanning)

### Getting Started

1. Clone the repository:

```bash
git clone https://github.com/yourusername/pan-scm-cicd.git
cd pan-scm-cicd
```

2. Install dependencies:

```bash
poetry install
```

3. Set up pre-commit hooks:

```bash
poetry run pre-commit install
```

4. Create your `.secrets.yaml` file (see `.secrets.yaml.example`).

### Development Workflow

Use the Makefile for common development tasks:

```bash
# Format code
make format

# Run linting
make lint

# Scan for secrets
make secrets-check

# Run tests
make test
make unit-test
make int-test
```

### Secret Protection

This repository uses several layers of protection to prevent accidental leakage of secrets:

1. **Pre-commit hooks**: Automatically detect secrets before they're committed
2. **Makefile target**: Run `make secrets-check` to manually scan for secrets
3. **CI/CD checks**: GitHub Actions automatically scans all PRs and pushes for secrets

## Environment Variables

You can also configure the application using environment variables:

```bash
# Set environment (development, production, etc.)
export ENV_FOR_DYNACONF=production

# Set SCM credentials
export PAN_CLIENT_ID=your-client-id
export PAN_CLIENT_SECRET=your-client-secret
export PAN_TSG_ID=your-tsg-id
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Submit a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
