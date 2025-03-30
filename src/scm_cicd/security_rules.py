"""
Security Rules Manager for Palo Alto Networks Strata Cloud Manager CICD Pipeline.

This module provides functionality to manage security rules within SCM, supporting
operations through a CICD pipeline with configuration stored in YAML files.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import ValidationError
from rich.console import Console
from rich.logging import RichHandler
from scm.client import Scm
from scm.exceptions import (
    AuthenticationError,
    InvalidObjectError,
    NameNotUniqueError,
)
from scm.models.security import (
    SecurityRuleCreateModel,
    SecurityRuleResponseModel,
    SecurityRuleRulebase,
    SecurityRuleUpdateModel,
)

from scm_cicd.config import settings

# Setup Rich console and logging
console = Console()
logging.basicConfig(
    level=settings.get("log_level", "INFO"),
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)],
)
logger = logging.getLogger("scm_cicd")


class SCMSecurityRuleManager:
    """Manager for SCM Security Rules in a CICD pipeline."""

    def __init__(self, testing: bool = False):
        """Initialize the SCM Security Rule Manager.

        Args:
            testing: If True, won't exit on credential errors (for testing purposes)
        """
        self.client = None
        self.testing = testing
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the SCM client with proper authentication."""
        try:
            # Get credentials from settings module
            client_id = settings.get("client_id", "")
            client_secret = settings.get("client_secret", "")
            tsg_id = settings.get("tsg_id", "")

            # Check if credentials are available
            if not all([client_id, client_secret, tsg_id]):
                logger.error("Missing required credentials. Please set them in .secrets.yaml or environment variables.")
                if not self.testing:
                    sys.exit(1)
                else:
                    # For testing, just return without initializing the client
                    return

            # Initialize the SCM client
            self.client = Scm(
                client_id=client_id,
                client_secret=client_secret,
                tsg_id=tsg_id,
                api_base_url=settings.get("api_base_url", "https://api.strata.paloaltonetworks.com"),
                token_url=settings.get("token_url", "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"),
                log_level=settings.get("log_level", "INFO"),
            )
            logger.info("SCM client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SCM client: {str(e)}")
            if not self.testing:
                sys.exit(1)

    def _get_rulebase_enum(self, rulebase: str) -> SecurityRuleRulebase:
        """Convert string rulebase to SecurityRuleRulebase enum.

        Args:
            rulebase: Rulebase string ('pre' or 'post')

        Returns:
            SecurityRuleRulebase enum
        """
        if isinstance(rulebase, SecurityRuleRulebase):
            return rulebase

        if rulebase.lower() == "pre":
            return SecurityRuleRulebase.PRE
        elif rulebase.lower() == "post":
            return SecurityRuleRulebase.POST
        else:
            raise ValueError(f"Invalid rulebase: {rulebase}. Must be 'pre' or 'post'")

    def load_rules_from_file(self, file_path: Union[str, Path]) -> List[SecurityRuleCreateModel]:
        """Load security rule configurations from a JSON or YAML file.

        Args:
            file_path: Path to the configuration file

        Returns:
            List of SecurityRuleCreateModel objects
        """
        file_path = Path(file_path)
        try:
            with open(file_path, "r") as f:
                if file_path.suffix.lower() in [".yaml", ".yml"]:
                    import yaml

                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            # Convert to list if it's a single object
            if isinstance(data, dict):
                data = [data]

            # Validate each rule against the SDK model
            return [SecurityRuleCreateModel(**rule) for rule in data]
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {file_path}")
            return []
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            logger.error(f"Error parsing configuration file: {str(e)}")
            return []
        except ValidationError as e:
            logger.error(f"Invalid rule configuration: {str(e)}")
            return []

    def create_rule(self, rule: SecurityRuleCreateModel, rulebase: str = "pre") -> Optional[SecurityRuleResponseModel]:
        """Create a security rule in SCM.

        Args:
            rule: Security rule configuration
            rulebase: Rulebase to create the rule in (pre or post)

        Returns:
            Created rule or None if creation failed
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            # Convert the rulebase string to enum
            rule_rulebase = self._get_rulebase_enum(rulebase)

            # Create rule using SCM SDK with proper parameters
            response = self.client.security_rule.create(rule.model_dump(exclude_none=True), rulebase=rule_rulebase)
            logger.info(f"Created security rule: {rule.name}")
            return response
        except AuthenticationError:
            logger.error("Authentication failed. Check your credentials.")
        except NameNotUniqueError:
            logger.error(f"Rule name '{rule.name}' already exists.")
        except InvalidObjectError as e:
            logger.error(f"Invalid rule configuration: {str(e)}")
        except Exception as e:
            logger.error(f"Error creating rule: {str(e)}")
        return None

    def update_rule(self, rule: SecurityRuleCreateModel, rulebase: str = "pre") -> Optional[SecurityRuleResponseModel]:
        """Update a security rule in SCM.

        Args:
            rule: Security rule configuration
            rulebase: Rulebase where the rule exists (pre or post)

        Returns:
            Updated rule or None if update failed
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            # Determine container type from the model
            container_type = None
            container = None
            if rule.folder:
                container_type = "folder"
                container = rule.folder
            elif rule.snippet:
                container_type = "snippet"
                container = rule.snippet
            elif rule.device:
                container_type = "device"
                container = rule.device
            else:
                logger.error("No container specified in rule model")
                return None

            # First fetch the existing rule to get its ID
            existing = self.get_rule_by_name(rule.name, container, container_type, rulebase)

            if not existing:
                logger.error(f"Rule '{rule.name}' not found in {container}")
                return None

            # Convert to UpdateModel and include the rule ID
            rule_dict = rule.model_dump(exclude_none=True)
            rule_id = existing.id

            # Create an update model with the existing data and ID
            update_model = SecurityRuleUpdateModel(**rule_dict)
            update_model.id = rule_id

            # Convert the rulebase string to enum
            rule_rulebase = self._get_rulebase_enum(rulebase)

            # Update rule using SCM SDK
            response = self.client.security_rule.update(update_model, rulebase=rule_rulebase)
            logger.info(f"Updated security rule: {rule.name}")
            return response
        except Exception as e:
            logger.error(f"Error updating rule: {str(e)}")
        return None

    def get_rule_by_name(
        self, name: str, container: str, container_type: str = "folder", rulebase: str = "pre"
    ) -> Optional[SecurityRuleResponseModel]:
        """Get a rule by name and container.

        Args:
            name: Rule name
            container: Container name (folder, snippet, or device)
            container_type: Type of container ('folder', 'snippet', or 'device')
            rulebase: Rulebase to search in (pre or post)

        Returns:
            Rule model or None if not found
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            # Validate container_type
            if container_type not in ["folder", "snippet", "device"]:
                logger.error(f"Invalid container type: {container_type}")
                return None

            # Convert the rulebase string to enum
            rule_rulebase = self._get_rulebase_enum(rulebase)

            # Fetch rule using SCM SDK
            params = {container_type: container, "name": name}
            return self.client.security_rule.fetch(**params, rulebase=rule_rulebase)
        except Exception as e:
            logger.error(f"Error fetching rule: {str(e)}")
        return None

    def delete_rule(self, name: str, container: str, container_type: str = "folder", rulebase: str = "pre") -> bool:
        """Delete a security rule in SCM.

        Args:
            name: Rule name
            container: Container name (folder, snippet, or device)
            container_type: Type of container ('folder', 'snippet', or 'device')
            rulebase: Rulebase where the rule exists (pre or post)

        Returns:
            True if deletion was successful, False otherwise
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return False

        try:
            # First fetch the rule to get its ID
            rule = self.get_rule_by_name(name, container, container_type, rulebase)

            if not rule:
                logger.error(f"Rule '{name}' not found in {container}")
                return False

            # Get the rule ID
            rule_id = str(rule.id)

            # Convert the rulebase string to enum
            rule_rulebase = self._get_rulebase_enum(rulebase)

            # Delete rule using SCM SDK
            self.client.security_rule.delete(rule_id, rulebase=rule_rulebase)
            logger.info(f"Deleted security rule: {name}")
            return True
        except Exception as e:
            logger.error(f"Error deleting rule: {str(e)}")
        return False

    def list_rules(
        self, container: str, container_type: str = "folder", rulebase: str = "pre", exact_match: bool = False
    ) -> List[SecurityRuleResponseModel]:
        """List all security rules in a container.

        Args:
            container: Container name (folder, snippet, or device)
            container_type: Type of container ('folder', 'snippet', or 'device')
            rulebase: Rulebase to list rules from (pre or post)
            exact_match: If True, only return rules defined directly in the container

        Returns:
            List of security rules
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return []

        try:
            # Validate container_type
            if container_type not in ["folder", "snippet", "device"]:
                logger.error(f"Invalid container type: {container_type}")
                return []

            # Convert the rulebase string to enum
            rule_rulebase = self._get_rulebase_enum(rulebase)

            # List rules using SCM SDK
            params = {container_type: container}
            return self.client.security_rule.list(**params, rulebase=rule_rulebase, exact_match=exact_match)
        except Exception as e:
            logger.error(f"Error listing rules: {str(e)}")
        return []

    def commit(self, folders: List[str], description: str = "CICD automated commit", sync: bool = True) -> Dict[str, Any]:
        """Commit changes to SCM.

        Args:
            folders: List of folders to commit
            description: Commit description
            sync: Whether to wait for the commit to complete

        Returns:
            Commit result
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return {"status": "FAILED", "error": "SCM client not initialized"}

        try:
            result = self.client.commit(folders=folders, description=description, sync=sync)

            # Convert commit result to dict for consistency
            if hasattr(result, "model_dump"):
                result_dict = result.model_dump()
            else:
                result_dict = result

            status = result_dict.get("status")
            job_id = result_dict.get("job_id")

            if status == "SUCCESS":
                logger.info(f"Commit successful: {job_id}")
            else:
                logger.warning(f"Commit status: {status}")

            return result_dict
        except Exception as e:
            logger.error(f"Error committing changes: {str(e)}")
            return {"status": "FAILED", "error": str(e)}

    def apply_rules_from_file(self, file_path: Union[str, Path], rulebase: str = "pre", commit_changes: bool = False) -> bool:
        """Apply security rules from a configuration file.

        This method handles the create or update decision based on whether the rule exists.

        Args:
            file_path: Path to the rule configuration file
            rulebase: Rulebase to apply rules to (pre or post)
            commit_changes: Whether to commit changes after applying rules

        Returns:
            True if all rules were applied successfully, False otherwise
        """
        # Load and validate rules
        rules = self.load_rules_from_file(file_path)
        if not rules:
            logger.error("No valid rules found in configuration file")
            return False

        if self.client is None:
            logger.error("SCM client not initialized")
            return False

        # Apply the rules
        success, affected_folders = self._apply_rules(rules, rulebase)

        # Commit changes if requested and there are affected folders
        if commit_changes and affected_folders and success:
            commit_result = self.commit(list(affected_folders))
            # Check both the status and look for job_id to determine success
            # The SDK sometimes returns None for status even when commit is successful
            status = commit_result.get("status")
            job_id = commit_result.get("job_id")

            if job_id and (status == "SUCCESS" or status is None):
                logger.info(f"Commit successful with job ID: {job_id}")
            else:
                logger.warning(f"Commit may have failed. Status: {status}")
                success = False

        return success

    def _apply_rules(self, rules: List[SecurityRuleCreateModel], rulebase: str) -> tuple[bool, set[str]]:
        """Apply a list of security rules.

        Args:
            rules: List of security rules to apply
            rulebase: Rulebase to apply rules to (pre or post)

        Returns:
            Tuple of (success, affected_folders)
        """
        success = True
        affected_folders = set()

        # Group rules by container to minimize API calls
        container_rules = {}
        for rule in rules:
            # Get container info
            container_info = self._get_container_info(rule)
            if not container_info:
                logger.error(f"No container specified for rule: {rule.name}")
                success = False
                continue

            container, container_type = container_info

            # Track folder for commits
            if container_type == "folder":
                affected_folders.add(container)

            # Group by container and type
            key = (container, container_type)
            if key not in container_rules:
                container_rules[key] = []
            container_rules[key].append(rule)

        # Process rules by container
        for (container, container_type), container_rule_list in container_rules.items():
            # Get existing rules in this container
            existing_rules = self.list_rules(container, container_type=container_type, rulebase=rulebase, exact_match=True)

            # Create a lookup map for faster access
            existing_rule_map = {rule.name: rule for rule in existing_rules}

            # Apply each rule
            for rule in container_rule_list:
                result = self._apply_single_rule_with_lookup(rule, container, container_type, rulebase, existing_rule_map)
                if not result:
                    success = False

        return success, affected_folders

    def _get_container_info(self, rule: SecurityRuleCreateModel) -> Optional[tuple[str, str]]:
        """Get container information from a rule.

        Args:
            rule: Security rule to get container information from

        Returns:
            Tuple of (container, container_type) or None if container not found
        """
        container_type = None
        container = None

        if rule.folder:
            container_type = "folder"
            container = rule.folder
        elif rule.snippet:
            container_type = "snippet"
            container = rule.snippet
        elif rule.device:
            container_type = "device"
            container = rule.device
        else:
            logger.error(f"No container specified for rule: {rule.name}")
            return None

        return container, container_type

    def _apply_single_rule_with_lookup(
        self, rule: SecurityRuleCreateModel, container: str, container_type: str, rulebase: str, existing_rule_map: dict
    ) -> bool:
        """Apply a single security rule using a lookup of existing rules.

        Args:
            rule: Security rule to apply
            container: Container name
            container_type: Container type (folder, snippet, or device)
            rulebase: Rulebase to apply the rule to
            existing_rule_map: Dictionary mapping rule names to existing rule objects

        Returns:
            True if the rule was applied successfully, False otherwise
        """
        try:
            # Check if the rule exists in our lookup map
            if rule.name in existing_rule_map:
                # Get the existing rule with its ID
                existing_rule = existing_rule_map[rule.name]

                # For updating, we need to create a separate update model with the ID
                update_data = rule.model_dump(exclude_none=True)

                # Make sure to set the ID field for the update
                update_data["id"] = existing_rule.id

                # Update the rule using the SDK's update method
                logger.info(f"Updating existing rule: {rule.name}")
                result = self.update_rule_by_id(update_data, rulebase)
            else:
                # Create a new rule
                logger.info(f"Creating new rule: {rule.name}")
                result = self.create_rule(rule, rulebase)

            return result is not None
        except Exception as e:
            logger.error(f"Error applying rule {rule.name}: {str(e)}")
            return False

    def update_rule_by_id(self, rule_data: dict, rulebase: str):
        """Update a security rule by its ID.

        Args:
            rule_data: Dictionary containing rule data including the ID
            rulebase: The rulebase to update (pre or post)

        Returns:
            Updated rule data or None if there was an error
        """
        try:
            # Create an update model with the data including ID
            update_model = SecurityRuleUpdateModel(**rule_data)

            # Update the rule
            result = self.client.security_rule.update(update_model, rulebase=self._get_rulebase_enum(rulebase))
            return result
        except ValidationError as e:
            logger.error(f"Error validating update data: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error updating rule: {str(e)}")
            return None
