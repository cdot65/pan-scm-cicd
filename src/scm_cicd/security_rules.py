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

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from rich.console import Console
from rich.logging import RichHandler
from scm.client import Scm
from scm.exceptions import (
    AuthenticationError,
    InvalidObjectError,
    NameNotUniqueError,
    ObjectNotPresentError,
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


class SecurityRuleConfig(BaseModel):
    """Security Rule Configuration Model based on SCM SDK models."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(..., description="Name of the rule")
    folder: Optional[str] = Field(None, description="Folder where rule is defined")
    snippet: Optional[str] = Field(None, description="Snippet where rule is defined")
    device: Optional[str] = Field(None, description="Device where rule is defined")
    disabled: bool = Field(False, description="Whether the rule is disabled")
    description: Optional[str] = Field(None, description="Description of the rule")
    from_: List[str] = Field(default=["any"], description="Source security zones")
    source: List[str] = Field(default=["any"], description="Source addresses")
    to_: List[str] = Field(default=["any"], description="Destination security zones")
    destination: List[str] = Field(default=["any"], description="Destination addresses")
    application: List[str] = Field(default=["any"], description="Applications")
    service: List[str] = Field(default=["any"], description="Services")
    action: str = Field("allow", description="Rule action (allow/deny/drop/reset-client/reset-server/reset-both)")
    profile_setting: Optional[Dict[str, Any]] = Field(None, description="Security profile settings")
    log_setting: Optional[str] = Field(None, description="Log forwarding profile")
    log_start: Optional[bool] = Field(None, description="Log at session start")
    log_end: Optional[bool] = Field(None, description="Log at session end")
    tag: Optional[List[str]] = Field(None, description="List of tags")


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

    def load_rules_from_file(self, file_path: Union[str, Path]) -> List[SecurityRuleConfig]:
        """Load security rule configurations from a JSON or YAML file.

        Args:
            file_path: Path to the configuration file

        Returns:
            List of SecurityRuleConfig objects
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

            # Validate each rule against our model
            return [SecurityRuleConfig(**rule) for rule in data]
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {file_path}")
            return []
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            logger.error(f"Error parsing configuration file: {str(e)}")
            return []
        except ValidationError as e:
            logger.error(f"Invalid rule configuration: {str(e)}")
            return []

    def create_rule(self, rule: SecurityRuleConfig, rulebase: str = "pre") -> Optional[Dict[str, Any]]:
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
            # Convert to dict for SDK
            rule_dict = rule.model_dump(exclude_none=True)

            # Create rule using SCM SDK
            response = self.client.security_rule.create(rule_dict, rulebase=rulebase)
            logger.info(f"Created security rule: {rule.name}")
            # Handle if response is a model object and not a dictionary
            if hasattr(response, "model_dump"):
                return response.model_dump()
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

    def update_rule(self, rule: SecurityRuleConfig, rulebase: str = "pre") -> Optional[Dict[str, Any]]:
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
            # First fetch the existing rule to get its ID
            existing = self.get_rule_by_name(rule.name, rule.folder, rulebase)

            if not existing:
                logger.error(f"Rule '{rule.name}' not found in {rule.folder or rule.snippet or rule.device}")
                return None

            # Convert to dict for SDK and include the rule ID
            rule_dict = rule.model_dump(exclude_none=True)
            rule_dict["id"] = existing.get("id") if isinstance(existing, dict) else getattr(existing, "id", None)

            # Update rule using SCM SDK
            response = self.client.security_rule.update(rule_dict)
            logger.info(f"Updated security rule: {rule.name}")
            # Handle if response is a model object and not a dictionary
            if hasattr(response, "model_dump"):
                return response.model_dump()
            return response
        except AuthenticationError:
            logger.error("Authentication failed. Check your credentials.")
        except ObjectNotPresentError:
            logger.error(f"Rule '{rule.name}' not found.")
        except InvalidObjectError as e:
            logger.error(f"Invalid rule configuration: {str(e)}")
        except Exception as e:
            logger.error(f"Error updating rule: {str(e)}")
        return None

    def get_rule_by_name(self, name: str, container: str, rulebase: str = "pre") -> Optional[Dict[str, Any]]:
        """Get a rule by name and container.

        Args:
            name: Rule name
            container: Container name (folder, snippet, or device)
            rulebase: Rulebase to search in (pre or post)

        Returns:
            Rule dict or None if not found
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            container_type = self._determine_container_type(container)
            if not container_type:
                logger.error("Unable to determine container type")
                return None

            # Fetch rule using SCM SDK
            params = {container_type: container, "name": name}
            response = self.client.security_rule.fetch(**params, rulebase=rulebase)
            # Handle if response is a model object and not a dictionary
            if hasattr(response, "model_dump"):
                return response.model_dump()
            return response
        except ObjectNotPresentError:
            logger.debug(f"Rule '{name}' not found in {container}")
        except Exception as e:
            logger.error(f"Error fetching rule: {str(e)}")
        return None

    def delete_rule(self, name: str, container: str, rulebase: str = "pre") -> bool:
        """Delete a security rule in SCM.

        Args:
            name: Rule name
            container: Container name (folder, snippet, or device)
            rulebase: Rulebase where the rule exists (pre or post)

        Returns:
            True if deletion was successful, False otherwise
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return False

        try:
            # First fetch the rule to get its ID
            rule = self.get_rule_by_name(name, container, rulebase)

            if not rule:
                logger.error(f"Rule '{name}' not found in {container}")
                return False

            # Get the rule ID, handling both dict and model object
            rule_id = rule.get("id") if isinstance(rule, dict) else getattr(rule, "id", None)
            if not rule_id:
                logger.error(f"Rule '{name}' found but has no ID")
                return False

            # Delete rule using SCM SDK
            self.client.security_rule.delete(rule_id, rulebase=rulebase)
            logger.info(f"Deleted security rule: {name}")
            return True
        except AuthenticationError:
            logger.error("Authentication failed. Check your credentials.")
        except ObjectNotPresentError:
            logger.error(f"Rule '{name}' not found.")
        except Exception as e:
            logger.error(f"Error deleting rule: {str(e)}")
        return False

    def list_rules(self, container: str, rulebase: str = "pre") -> List[Dict[str, Any]]:
        """List all security rules in a container.

        Args:
            container: Container name (folder, snippet, or device)
            rulebase: Rulebase to list rules from (pre or post)

        Returns:
            List of security rules
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return []

        try:
            container_type = self._determine_container_type(container)
            if not container_type:
                logger.error("Unable to determine container type")
                return []

            # List rules using SCM SDK
            params = {container_type: container}
            response = self.client.security_rule.list(**params, rulebase=rulebase)

            # Convert model objects to dictionaries if needed
            if response and hasattr(response[0], "model_dump"):
                return [rule.model_dump() for rule in response]
            return response
        except Exception as e:
            logger.error(f"Error listing rules: {str(e)}")
        return []

    def _determine_container_type(self, container: str) -> Optional[str]:
        """Determine the container type based on naming conventions or API calls.

        This is a simple implementation that assumes folders, snippets, and devices
        follow certain naming conventions. In a real-world scenario, you might want
        to verify with actual API calls.

        Args:
            container: Container name

        Returns:
            Container type (folder, snippet, or device) or None if undetermined
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        # This is a simplistic approach - in production you might want to
        # implement more sophisticated detection or allow explicit specification
        try:
            # Try to check if it's a folder
            self.client.security_rule.list(folder=container, rulebase="pre", limit=1)
            return "folder"
        except Exception:
            try:
                # Try to check if it's a snippet
                self.client.security_rule.list(snippet=container, rulebase="pre", limit=1)
                return "snippet"
            except Exception:
                try:
                    # Try to check if it's a device
                    self.client.security_rule.list(device=container, rulebase="pre", limit=1)
                    return "device"
                except Exception:
                    return None

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

            # Handle if result is a model object
            if hasattr(result, "model_dump"):
                result_dict = result.model_dump()
                status = result_dict.get("status")
                job_id = result_dict.get("job_id")
            else:
                status = result.get("status")
                job_id = result.get("job_id")
                result_dict = result

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
        rules = self.load_rules_from_file(file_path)
        if not rules:
            logger.error("No valid rules found in configuration file")
            return False

        if self.client is None:
            logger.error("SCM client not initialized")
            return False

        success = True
        affected_folders = set()

        for rule in rules:
            container = rule.folder or rule.snippet or rule.device
            if not container:
                logger.error(f"No container specified for rule: {rule.name}")
                success = False
                continue

            # Check if the rule exists
            existing = self.get_rule_by_name(rule.name, container, rulebase)

            if existing:
                # Update existing rule
                result = self.update_rule(rule, rulebase)
            else:
                # Create new rule
                result = self.create_rule(rule, rulebase)

            if not result:
                success = False

            # Track affected folders for commit
            if rule.folder:
                affected_folders.add(rule.folder)

        # Commit changes if requested and there are affected folders
        if commit_changes and affected_folders and success:
            commit_result = self.commit(list(affected_folders))
            if commit_result.get("status") != "SUCCESS":
                success = False

        return success
