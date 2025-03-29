"""
Unit tests for the CLI module.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scm_cicd.cli import app


@pytest.fixture
def mock_manager():
    """Mock SCMSecurityRuleManager."""
    with patch("scm_cicd.cli.SCMSecurityRuleManager") as mock:
        manager_instance = MagicMock()
        mock.return_value = manager_instance
        yield manager_instance


class TestCLI:
    """Tests for the CLI commands."""

    def test_apply_success(self, cli_runner, mock_manager, temp_rule_file):
        """Test successful rule application."""
        yaml_file = temp_rule_file["yaml"]
        mock_manager.apply_rules_from_file.return_value = True

        result = cli_runner.invoke(app, ["apply", str(yaml_file)])

        assert result.exit_code == 0
        assert "Successfully applied all rules" in result.stdout
        mock_manager.apply_rules_from_file.assert_called_once_with(Path(str(yaml_file)), rulebase="pre", commit_changes=False)

    def test_apply_failure(self, cli_runner, mock_manager, temp_rule_file):
        """Test failed rule application."""
        yaml_file = temp_rule_file["yaml"]
        mock_manager.apply_rules_from_file.return_value = False

        result = cli_runner.invoke(app, ["apply", str(yaml_file)])

        assert result.exit_code == 1
        assert "Failed to apply some or all rules" in result.stdout

    def test_apply_with_commit(self, cli_runner, mock_manager, temp_rule_file):
        """Test rule application with commit."""
        yaml_file = temp_rule_file["yaml"]
        mock_manager.apply_rules_from_file.return_value = True

        result = cli_runner.invoke(app, ["apply", str(yaml_file), "--commit"])

        assert result.exit_code == 0
        mock_manager.apply_rules_from_file.assert_called_once_with(Path(str(yaml_file)), rulebase="pre", commit_changes=True)

    def test_apply_with_dry_run(self, cli_runner, mock_manager, temp_rule_file):
        """Test rule application with dry run."""
        yaml_file = temp_rule_file["yaml"]
        mock_manager.load_rules_from_file.return_value = [MagicMock(name="test-rule", folder="Test")]

        result = cli_runner.invoke(app, ["apply", str(yaml_file), "--dry-run"])

        assert result.exit_code == 0
        assert "Configuration valid" in result.stdout
        mock_manager.apply_rules_from_file.assert_not_called()

    def test_list_success(self, cli_runner, mock_manager):
        """Test listing rules."""
        mock_manager.list_rules.return_value = [
            {
                "name": "rule1",
                "source": ["any"],
                "destination": ["any"],
                "application": ["any"],
                "service": ["any"],
                "action": "allow",
            },
            {
                "name": "rule2",
                "source": ["10.0.0.0/8"],
                "destination": ["any"],
                "application": ["web-browsing"],
                "service": ["application-default"],
                "action": "deny",
            },
        ]

        result = cli_runner.invoke(app, ["list", "Global"])

        assert result.exit_code == 0
        assert "rule1" in result.stdout
        assert "rule2" in result.stdout
        mock_manager.list_rules.assert_called_once_with("Global", rulebase="pre")

    def test_list_empty(self, cli_runner, mock_manager):
        """Test listing with no rules."""
        mock_manager.list_rules.return_value = []

        result = cli_runner.invoke(app, ["list", "Global"])

        assert result.exit_code == 0
        assert "No rules found in Global" in result.stdout

    def test_delete_success(self, cli_runner, mock_manager):
        """Test successful rule deletion."""
        mock_manager.delete_rule.return_value = True

        result = cli_runner.invoke(app, ["delete", "test-rule", "Global"])

        assert result.exit_code == 0
        assert "Successfully deleted rule test-rule" in result.stdout
        mock_manager.delete_rule.assert_called_once_with("test-rule", "Global", rulebase="pre")

    def test_delete_failure(self, cli_runner, mock_manager):
        """Test failed rule deletion."""
        mock_manager.delete_rule.return_value = False

        result = cli_runner.invoke(app, ["delete", "test-rule", "Global"])

        assert result.exit_code == 1
        assert "Failed to delete rule test-rule" in result.stdout

    def test_delete_with_commit(self, cli_runner, mock_manager):
        """Test rule deletion with commit."""
        mock_manager.delete_rule.return_value = True
        mock_manager.commit.return_value = {"status": "SUCCESS"}

        result = cli_runner.invoke(app, ["delete", "test-rule", "Global", "--commit"])

        assert result.exit_code == 0
        mock_manager.delete_rule.assert_called_once()
        mock_manager.commit.assert_called_once()

    def test_commit_success(self, cli_runner, mock_manager):
        """Test successful commit."""
        mock_manager.commit.return_value = {"status": "SUCCESS", "job_id": "job-123456"}

        result = cli_runner.invoke(app, ["commit", "Global", "--message", "Test commit"])

        assert result.exit_code == 0
        assert "Commit successful" in result.stdout
        mock_manager.commit.assert_called_once_with(["Global"], description="Test commit")

    def test_commit_failure(self, cli_runner, mock_manager):
        """Test failed commit."""
        mock_manager.commit.return_value = {"status": "FAILED", "error": "Something went wrong"}

        result = cli_runner.invoke(app, ["commit", "Global"])

        assert result.exit_code == 1
        assert "Commit failed" in result.stdout
        assert "Something went wrong" in result.stdout
