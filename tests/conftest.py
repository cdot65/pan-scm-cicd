"""
Pytest configuration file for SCM CICD tests.

This module provides fixtures and configuration for both unit and integration tests.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from scm_cicd.security_rules import SCMSecurityRuleManager, SecurityRuleConfig
from typer.testing import CliRunner

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Integration test fixtures - these connect to real SCM API
# Skip these tests if running in CI environment or if explicitly skipped


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def example_rule_dict():
    """Sample security rule dictionary for testing."""
    return {
        "name": "test-rule",
        "folder": "test-folder",
        "description": "Test rule for unit tests",
        "from_": ["trust"],
        "source": ["192.168.1.1"],
        "to_": ["untrust"],
        "destination": ["any"],
        "application": ["web-browsing"],
        "service": ["application-default"],
        "action": "allow",
        "log_end": True,
        "tag": ["test", "pytest"],
    }


@pytest.fixture
def example_rule_config(example_rule_dict):
    """Return an example SecurityRuleConfig object."""
    return SecurityRuleConfig(**example_rule_dict)


@pytest.fixture
def example_rule_response(example_rule_dict):
    """Return an example API response for a security rule."""
    response = example_rule_dict.copy()
    response["id"] = "12345678-1234-5678-1234-567812345678"
    return response


@pytest.fixture
def mock_scm_client():
    """Mock SCM client."""
    mock = MagicMock()
    mock.security_rule = MagicMock()
    return mock


@pytest.fixture
def mock_security_rule_manager(mock_scm_client):
    """Mock SCMSecurityRuleManager with mocked SCM client."""
    with patch("scm_cicd.security_rules.Scm", return_value=mock_scm_client):
        manager = SCMSecurityRuleManager(testing=True)
        manager.client = mock_scm_client
        yield manager


@pytest.fixture
def temp_rule_file(tmp_path, example_rule_dict):
    """Create a temporary rule file for testing."""
    # Create YAML file
    yaml_file = tmp_path / "test_rule.yaml"
    with open(yaml_file, "w") as f:
        yaml.dump([example_rule_dict], f)

    # Create JSON file
    json_file = tmp_path / "test_rule.json"
    with open(json_file, "w") as f:
        json.dump([example_rule_dict], f)

    return {"yaml": yaml_file, "json": json_file}


# Integration test fixtures - these connect to real SCM API
# Skip these tests if running in CI environment or if explicitly skipped


@pytest.fixture
def integration_check():
    """Skip integration tests if running in CI or explicitly disabled."""
    if os.environ.get("CI") or os.environ.get("SKIP_INTEGRATION_TESTS"):
        pytest.skip("Skipping integration tests in CI or when explicitly disabled")
    # Check if .secrets.yaml has valid credentials
    secrets_file = project_root / ".secrets.yaml"
    if not secrets_file.exists():
        pytest.skip("Skipping integration tests: .secrets.yaml not found")

    # Try to load the secrets file to see if it has credentials
    try:
        with open(secrets_file, "r") as f:
            secrets = yaml.safe_load(f)

        env = os.environ.get("ENV_FOR_DYNACONF", "development")
        if env not in secrets:
            pytest.skip(f"Skipping integration tests: {env} environment not found in .secrets.yaml")

        env_secrets = secrets[env]
        if not all([env_secrets.get("client_id"), env_secrets.get("client_secret"), env_secrets.get("tsg_id")]):
            pytest.skip(f"Skipping integration tests: Missing credentials in .secrets.yaml for {env}")
    except Exception as e:
        pytest.skip(f"Skipping integration tests: Error loading .secrets.yaml: {str(e)}")


@pytest.fixture
def real_security_rule_manager(integration_check):
    """Create a real SCMSecurityRuleManager instance connected to SCM API."""
    return SCMSecurityRuleManager(testing=True)
