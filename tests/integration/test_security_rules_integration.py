"""
Integration tests for the security_rules module.

These tests connect to the actual SCM API using credentials from .secrets.yaml.
They will be skipped if running in CI or if the credentials are not available.
"""

import tempfile

import pytest
import yaml

from scm_cicd.security_rules import SecurityRuleConfig


@pytest.mark.integration
class TestSCMSecurityRuleManagerIntegration:
    """Integration tests for SCMSecurityRuleManager."""

    def test_connection(self, real_security_rule_manager):
        """Test that we can connect to the SCM API."""
        # This test will be skipped if we can't connect
        assert real_security_rule_manager.client is not None

    def test_list_rules(self, real_security_rule_manager):
        """Test listing rules from a real folder."""
        # Try to list rules from "Shared" folder which typically exists
        rules = real_security_rule_manager.list_rules("Shared")
        # We don't assert on the content, just that it returned something
        assert isinstance(rules, list)

    def test_load_rules_from_file(self, real_security_rule_manager):
        """Test loading rules from a file."""
        # Create a temporary rule file
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w+") as f:
            yaml.dump(
                [
                    {
                        "name": "test-integration-rule",
                        "folder": "Shared",
                        "description": "Test rule for integration testing",
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

            # Load the rules from the file
            rules = real_security_rule_manager.load_rules_from_file(f.name)

            # Check the rules were loaded correctly
            assert len(rules) == 1
            assert isinstance(rules[0], SecurityRuleConfig)
            assert rules[0].name == "test-integration-rule"
            assert rules[0].folder == "Shared"

    @pytest.mark.skip(reason="This test would create a real rule in SCM")
    def test_create_and_delete_rule(self, real_security_rule_manager):
        """Test creating and then deleting a rule.

        This test is skipped by default to avoid creating real rules.
        Remove the skip mark to run it when needed.
        """
        # Create a test rule
        test_rule = SecurityRuleConfig(
            name="test-integration-rule-temp",
            folder="Shared",
            description="Temporary test rule for integration testing",
            from_=["trust"],
            to_=["untrust"],
            source=["10.0.0.0/8"],
            destination=["any"],
            application=["web-browsing"],
            service=["application-default"],
            action="allow",
        )

        # Create the rule
        response = real_security_rule_manager.create_rule(test_rule)
        assert response is not None
        assert "id" in response

        # Try to get the rule by name
        retrieved = real_security_rule_manager.get_rule_by_name("test-integration-rule-temp", "Shared")
        assert retrieved is not None
        assert retrieved["name"] == "test-integration-rule-temp"

        # Clean up by deleting the rule
        deleted = real_security_rule_manager.delete_rule("test-integration-rule-temp", "Shared")
        assert deleted is True
