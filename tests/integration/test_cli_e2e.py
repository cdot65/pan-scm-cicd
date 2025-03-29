"""
End-to-end tests for the CLI interface.

These tests use the actual CLI interface with real credentials from .secrets.yaml
to interact with the SCM API. They will be skipped if the credentials are not available.
"""

import tempfile
from pathlib import Path

import pytest
import yaml
from scm_cicd.cli import app


@pytest.mark.integration
class TestCLIEndToEnd:
    """End-to-end tests for CLI commands."""

    @pytest.fixture
    def temp_rule_yaml(self):
        """Create a temporary rule file for testing."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w+", delete=False) as f:
            yaml.dump(
                [
                    {
                        "name": "test-e2e-rule",
                        "folder": "Shared",
                        "description": "Test rule for E2E testing",
                        "from_": ["trust"],
                        "to_": ["untrust"],
                        "source": ["10.0.0.0/8"],
                        "destination": ["any"],
                        "application": ["web-browsing"],
                        "service": ["application-default"],
                        "action": "allow",
                    }
                ],
                f,
            )
            f.flush()
            yield Path(f.name)
            # File will be cleaned up by the OS

    def test_list_command(self, cli_runner, integration_check):
        """Test the 'list' command with real credentials."""
        result = cli_runner.invoke(app, ["list", "Shared"])

        # Verify the command ran successfully
        assert result.exit_code == 0
        # Look for expected output indicating the command worked
        assert "Listing rules in" in result.stdout

    def test_dry_run_command(self, cli_runner, temp_rule_yaml, integration_check):
        """Test the 'apply' command with --dry-run flag."""
        result = cli_runner.invoke(app, ["apply", str(temp_rule_yaml), "--dry-run"])

        # Verify the command ran successfully
        assert result.exit_code == 0
        # Check for validation success
        assert "Configuration valid" in result.stdout
        assert "test-e2e-rule" in result.stdout

    @pytest.mark.skip(reason="This test would create a real rule in SCM")
    def test_apply_and_delete_command(self, cli_runner, temp_rule_yaml, integration_check):
        """Test the full cycle: apply a rule and then delete it.

        This test is skipped by default to avoid creating real rules.
        Remove the skip mark to run it when needed.
        """
        # Step 1: Apply the rule
        apply_result = cli_runner.invoke(app, ["apply", str(temp_rule_yaml)])
        assert apply_result.exit_code == 0
        assert "Successfully applied all rules" in apply_result.stdout

        # Step 2: Verify it was created by listing it
        list_result = cli_runner.invoke(app, ["list", "Shared"])
        assert list_result.exit_code == 0
        assert "test-e2e-rule" in list_result.stdout

        # Step 3: Delete the rule
        delete_result = cli_runner.invoke(app, ["delete", "test-e2e-rule", "Shared"])
        assert delete_result.exit_code == 0
        assert "Successfully deleted rule" in delete_result.stdout

        # Step 4: Verify it was deleted
        list_result_after = cli_runner.invoke(app, ["list", "Shared"])
        assert list_result_after.exit_code == 0
        # This could fail if the rule already existed before the test
        # or if there are other rules with similar names
        assert "test-e2e-rule" not in list_result_after.stdout
