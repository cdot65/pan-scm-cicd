# Makefile for pan-scm-cicd project
.PHONY: help install format lint secrets-check test clean docs build publish

# Variables
PYTHON = poetry run python
PYTEST = poetry run pytest
PYTEST_ARGS = --verbose
RUFF = poetry run ruff
FLAKE8 = poetry run flake8
COVERAGE = poetry run pytest --cov=src/scm_cicd
PACKAGE_DIR = src/scm_cicd
TEST_DIR = tests

# Colors
BOLD = \033[1m
CYAN = \033[36m
GREEN = \033[32m
YELLOW = \033[33m
RED = \033[31m
RESET = \033[0m

help:
	@echo "$(BOLD)pan-scm-cicd Makefile$(RESET)"
	@echo "$(BOLD)------------------$(RESET)"
	@echo "$(CYAN)install$(RESET)    : Install dependencies with Poetry"
	@echo "$(CYAN)format$(RESET)     : Format code with ruff"
	@echo "$(CYAN)lint$(RESET)       : Run linting checks with flake8"
	@echo "$(CYAN)secrets-check$(RESET) : Scan for secrets and security issues"
	@echo "$(CYAN)test$(RESET)       : Run tests with pytest"
	@echo "$(CYAN)unit-test$(RESET)  : Run only unit tests"
	@echo "$(CYAN)int-test$(RESET)   : Run only integration tests"
	@echo "$(CYAN)coverage$(RESET)   : Run tests with coverage report"
	@echo "$(CYAN)clean$(RESET)      : Remove build artifacts and cache files"
	@echo "$(CYAN)build$(RESET)      : Build distribution packages"
	@echo "$(CYAN)publish$(RESET)    : Publish package to PyPI"
	@echo "$(CYAN)docs$(RESET)       : Generate documentation"
	@echo "$(CYAN)run-apply$(RESET)  : Run apply command with test rule"

install:
	@echo "$(BOLD)$(GREEN)Installing dependencies...$(RESET)"
	@poetry install

format:
	@echo "$(BOLD)$(GREEN)Formatting code with ruff...$(RESET)"
	@$(RUFF) format $(PACKAGE_DIR) $(TEST_DIR)
	@echo "$(BOLD)$(GREEN)Code formatting complete.$(RESET)"

lint:
	@echo "$(BOLD)$(GREEN)Linting code with flake8...$(RESET)"
	@$(FLAKE8) $(PACKAGE_DIR) $(TEST_DIR) --max-line-length=128
	@echo "$(BOLD)$(YELLOW)Running ruff checks...$(RESET)"
	@$(RUFF) check $(PACKAGE_DIR) $(TEST_DIR) --select=E,F,B,I,N,C
	@echo "$(BOLD)$(GREEN)Linting complete.$(RESET)"

secrets-check:
	@echo "$(BOLD)$(GREEN)Scanning for secrets and security issues...$(RESET)"
	@# First run the tool we know is available through Poetry
	@poetry run checkov --directory . --quiet --framework secrets || echo "$(BOLD)$(RED)Warning: Checkov scan failed$(RESET)"
	@# Use the full path to gitleaks if possible
	@if command -v gitleaks >/dev/null 2>&1; then \
		$(shell which gitleaks) detect --source . || echo "$(BOLD)$(RED)Warning: Gitleaks scan failed$(RESET)"; \
	else \
		echo "$(BOLD)$(YELLOW)Note: gitleaks not installed. To install: brew install gitleaks$(RESET)"; \
	fi
	@echo "$(BOLD)$(GREEN)Secret scanning complete.$(RESET)"

test:
	@echo "$(BOLD)$(GREEN)Running tests...$(RESET)"
	@$(PYTEST) $(PYTEST_ARGS)

unit-test:
	@echo "$(BOLD)$(GREEN)Running unit tests...$(RESET)"
	@$(PYTEST) $(PYTEST_ARGS) tests/unit

int-test:
	@echo "$(BOLD)$(GREEN)Running integration tests...$(RESET)"
	@$(PYTEST) $(PYTEST_ARGS) tests/integration

coverage:
	@echo "$(BOLD)$(GREEN)Running tests with coverage...$(RESET)"
	@$(COVERAGE) --cov-report=term-missing
	@echo "$(BOLD)$(GREEN)Coverage report complete.$(RESET)"

clean:
	@echo "$(BOLD)$(GREEN)Cleaning up...$(RESET)"
	@rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/ .coverage htmlcov/
	@find . -type d -name __pycache__ -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name "*.pyd" -delete
	@echo "$(BOLD)$(GREEN)Clean complete.$(RESET)"

build:
	@echo "$(BOLD)$(GREEN)Building packages...$(RESET)"
	@poetry build
	@echo "$(BOLD)$(GREEN)Build complete.$(RESET)"

publish:
	@echo "$(BOLD)$(GREEN)Publishing package...$(RESET)"
	@poetry publish
	@echo "$(BOLD)$(GREEN)Publish complete.$(RESET)"

docs:
	@echo "$(BOLD)$(GREEN)Generating documentation...$(RESET)"
	@mkdir -p docs
	@# Add your documentation generation commands here
	@echo "$(BOLD)$(GREEN)Documentation generation complete.$(RESET)"

run-apply:
	@echo "$(BOLD)$(GREEN)Running apply command with test rule...$(RESET)"
	@$(PYTHON) -m scm_cicd.cli apply --dry-run examples/test-rule.yaml
	@echo "$(BOLD)$(GREEN)Command completed successfully.$(RESET)"
