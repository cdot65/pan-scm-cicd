"""
Unit tests for the security_rules module.
"""

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from scm_cicd.security_rules import SecurityRuleConfig


class TestSecurityRuleConfig:
    """Tests for the SecurityRuleConfig model."""

    def test_valid_config(self, example_rule_dict):
        """Test creating a valid SecurityRuleConfig."""
        config = SecurityRuleConfig(**example_rule_dict)
        assert config.name == example_rule_dict["name"]
        assert config.folder == example_rule_dict["folder"]
        assert config.from_ == example_rule_dict["from_"]
        assert config.action == example_rule_dict["action"]

    def test_minimal_config(self):
        """Test creating a minimal SecurityRuleConfig."""
        minimal_config = {"name": "minimal-rule", "folder": "Test"}
        config = SecurityRuleConfig(**minimal_config)
        assert config.name == "minimal-rule"
        assert config.folder == "Test"
        assert config.from_ == ["any"]  # Default value
        assert config.action == "allow"  # Default value

    def test_invalid_config(self):
        """Test validation error with invalid config."""
        invalid_config = {
            "folder": "Test",  # Missing required 'name' field
        }
        with pytest.raises(ValidationError):
            SecurityRuleConfig(**invalid_config)

    def test_container_exclusivity(self):
        """Test that multiple container types are accepted by the model."""
        # This is valid at the model level - the API will handle validation
        config_dict = {
            "name": "test-rule",
            "folder": "Test",
            "snippet": "TestSnippet",
        }
        config = SecurityRuleConfig(**config_dict)
        assert config.folder == "Test"
        assert config.snippet == "TestSnippet"


class TestSCMSecurityRuleManager:
    """Tests for the SCMSecurityRuleManager class."""

    def test_load_rules_from_yaml(self, mock_security_rule_manager, temp_rule_file):
        """Test loading rules from a YAML file."""
        yaml_file = temp_rule_file["yaml"]
        rules = mock_security_rule_manager.load_rules_from_file(yaml_file)
        assert len(rules) == 1
        assert isinstance(rules[0], SecurityRuleConfig)
        assert rules[0].name == "test-rule"

    def test_load_rules_from_json(self, mock_security_rule_manager, temp_rule_file):
        """Test loading rules from a JSON file."""
        json_file = temp_rule_file["json"]
        rules = mock_security_rule_manager.load_rules_from_file(json_file)
        assert len(rules) == 1
        assert isinstance(rules[0], SecurityRuleConfig)
        assert rules[0].name == "test-rule"

    def test_load_rules_file_not_found(self, mock_security_rule_manager):
        """Test loading rules from a non-existent file."""
        rules = mock_security_rule_manager.load_rules_from_file("nonexistent.yaml")
        assert len(rules) == 0

    def test_create_rule(self, mock_security_rule_manager, example_rule_config, example_rule_response):
        """Test creating a security rule."""
        mock_security_rule_manager.client.security_rule.create.return_value = example_rule_response

        response = mock_security_rule_manager.create_rule(example_rule_config)

        assert response == example_rule_response
        mock_security_rule_manager.client.security_rule.create.assert_called_once()
        # Extract the first argument (rule_dict) from the call
        args, _ = mock_security_rule_manager.client.security_rule.create.call_args
        rule_dict = args[0]
        assert rule_dict["name"] == example_rule_config.name
        assert rule_dict["folder"] == example_rule_config.folder

    def test_update_rule(self, mock_security_rule_manager, example_rule_config, example_rule_response):
        """Test updating a security rule."""
        # Mock get_rule_by_name to return a rule with ID
        mock_security_rule_manager.get_rule_by_name = MagicMock(return_value=example_rule_response)
        mock_security_rule_manager.client.security_rule.update.return_value = example_rule_response

        response = mock_security_rule_manager.update_rule(example_rule_config)

        assert response == example_rule_response
        mock_security_rule_manager.client.security_rule.update.assert_called_once()
        # Verify the rule ID was included in the update
        args, _ = mock_security_rule_manager.client.security_rule.update.call_args
        rule_dict = args[0]
        assert rule_dict["id"] == example_rule_response["id"]

    def test_get_rule_by_name(self, mock_security_rule_manager, example_rule_response):
        """Test getting a rule by name."""
        mock_security_rule_manager._determine_container_type = MagicMock(return_value="folder")
        mock_security_rule_manager.client.security_rule.fetch.return_value = example_rule_response

        response = mock_security_rule_manager.get_rule_by_name("test-rule", "Test")

        assert response == example_rule_response
        mock_security_rule_manager.client.security_rule.fetch.assert_called_once()

    def test_delete_rule(self, mock_security_rule_manager, example_rule_response):
        """Test deleting a security rule."""
        # Mock get_rule_by_name to return a rule with ID
        mock_security_rule_manager.get_rule_by_name = MagicMock(return_value=example_rule_response)

        result = mock_security_rule_manager.delete_rule("test-rule", "Test")

        assert result is True
        mock_security_rule_manager.client.security_rule.delete.assert_called_once_with(
            example_rule_response["id"], rulebase="pre"
        )

    def test_apply_rules_from_file(self, mock_security_rule_manager, temp_rule_file, example_rule_response):
        """Test applying rules from a file."""
        # Mock the necessary methods
        mock_security_rule_manager.get_rule_by_name = MagicMock(return_value=None)  # Rule doesn't exist
        mock_security_rule_manager.create_rule = MagicMock(return_value=example_rule_response)
        mock_security_rule_manager.commit = MagicMock(return_value={"status": "SUCCESS"})

        yaml_file = temp_rule_file["yaml"]
        result = mock_security_rule_manager.apply_rules_from_file(yaml_file, commit_changes=True)

        assert result is True
        mock_security_rule_manager.create_rule.assert_called_once()
        mock_security_rule_manager.commit.assert_called_once()

    def test_determine_container_type(self, mock_security_rule_manager):
        """Test determining container type."""
        # Mock success response for folder
        mock_security_rule_manager.client.security_rule.list.return_value = []

        container_type = mock_security_rule_manager._determine_container_type("Test")

        assert container_type == "folder"
        mock_security_rule_manager.client.security_rule.list.assert_called_once()

    def test_commit(self, mock_security_rule_manager):
        """Test committing changes."""
        mock_security_rule_manager.client.commit.return_value = {"status": "SUCCESS", "job_id": "job-123456"}

        result = mock_security_rule_manager.commit(["Test"], description="Test commit")

        assert result["status"] == "SUCCESS"
        assert result["job_id"] == "job-123456"
        mock_security_rule_manager.client.commit.assert_called_once_with(folders=["Test"], description="Test commit", sync=True)
