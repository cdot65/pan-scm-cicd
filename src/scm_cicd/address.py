"""
Address Manager for Palo Alto Networks Strata Cloud Manager CICD Pipeline.

This module provides functionality to manage address objects within SCM, supporting
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
)
from scm.models.objects import (
    AddressCreateModel,
    AddressResponseModel,
    AddressUpdateModel,
)

from scm_cicd.config import settings

# Set up logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)],
)

logger = logging.getLogger("scm_cicd")


class SCMAddressManager:
    """Manages Address objects in Palo Alto Networks Strata Cloud Manager.

    This class provides functionality to create, list, update, and delete
    address objects in Strata Cloud Manager. It also provides functionality
    to apply address objects from configuration files.
    """

    def __init__(self, testing=False):
        """Initialize the SCM Address Manager.

        Args:
            testing: Whether to initialize the client in testing mode
        """
        self.client = None

        # Don't initialize the client in testing mode
        if not testing:
            self._initialize_client()

    def _initialize_client(self):
        """Initialize the SCM client."""
        try:
            # Initialize the client with credentials from settings
            self.client = Scm(
                client_id=settings.client_id,
                client_secret=settings.client_secret,
                tsg_id=settings.tsg_id,
                log_level=settings.log_level,
            )
            logger.info("SCM client initialized successfully")
        except AuthenticationError as e:
            logger.error(f"Authentication failed: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to initialize SCM client: {e}")
            sys.exit(1)

    def _determine_container_type(self, container_value: str) -> str:
        """Determine the container type based on API calls.

        Args:
            container_value: Container name

        Returns:
            Container type (folder, snippet, or device)
        """
        try:
            # Test if it's a folder
            folders = self.client.folder.list(filter=container_value)
            for folder in folders:
                if folder.name == container_value:
                    return "folder"

            # Test if it's a snippet
            snippets = self.client.snippet.list(filter=container_value)
            for snippet in snippets:
                if snippet.name == container_value:
                    return "snippet"

            # Test if it's a device
            devices = self.client.device.list(filter=container_value)
            for device in devices:
                if device.name == container_value:
                    return "device"

            # Default to folder if can't determine
            logger.warning(f"Unable to determine container type for {container_value}, defaulting to folder")
            return "folder"
        except Exception as e:
            logger.error(f"Error determining container type: {e}")
            return "folder"

    def load_addresses_from_file(self, file_path: Union[str, Path]) -> List[AddressCreateModel]:
        """Load address objects from a configuration file.

        Args:
            file_path: Path to the address configuration file

        Returns:
            List of validated AddressCreateModel objects
        """
        file_path = Path(file_path) if isinstance(file_path, str) else file_path

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        # Load the file content
        try:
            with open(file_path, "r") as f:
                if file_path.suffix.lower() in [".yaml", ".yml"]:
                    import yaml

                    data = yaml.safe_load(f)
                elif file_path.suffix.lower() == ".json":
                    data = json.load(f)
                else:
                    logger.error(f"Unsupported file format: {file_path.suffix}")
                    return []
        except Exception as e:
            logger.error(f"Error loading configuration file: {e}")
            return []

        if not data:
            logger.error("Configuration file is empty or invalid")
            return []

        # Ensure data is a list
        if not isinstance(data, list):
            data = [data]

        # Validate addresses against the model
        validated_addresses = []
        for idx, item in enumerate(data):
            try:
                address = AddressCreateModel(**item)
                validated_addresses.append(address)
            except ValidationError as e:
                logger.error(f"Validation error for address at position {idx}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error validating address at position {idx}: {e}")

        return validated_addresses

    def create_address(self, address: AddressCreateModel) -> Optional[AddressResponseModel]:
        """Create a new address object.

        Args:
            address: Address object to create

        Returns:
            Created address object or None if creation failed
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            # Get data as dictionary with None values excluded
            address_data = address.model_dump(exclude_none=True)
            result = self.client.address.create(address_data)
            logger.info(f"Created address object: {result.name}")
            return result
        except ValidationError as e:
            logger.error(f"Validation error creating address: {e}")
        except InvalidObjectError as e:
            logger.error(f"Error creating address: {e}")
        except Exception as e:
            logger.error(f"Unexpected error creating address: {e}")

        return None

    def update_address(self, address: AddressUpdateModel) -> Optional[AddressResponseModel]:
        """Update an existing address object.

        Args:
            address: Address object to update

        Returns:
            Updated address object or None if update failed
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            result = self.client.address.update(address)
            logger.info(f"Updated address object: {result.name}")
            return result
        except ValidationError as e:
            logger.error(f"Validation error updating address: {e}")
        except InvalidObjectError as e:
            logger.error(f"Error updating address: {e}")
        except Exception as e:
            logger.error(f"Unexpected error updating address: {e}")

        return None

    def get_address_by_name(self, name: str, container: str, container_type: str) -> Optional[AddressResponseModel]:
        """Get an address object by name.

        Args:
            name: Name of the address object to get
            container: Container name (folder, snippet, or device)
            container_type: Container type (folder, snippet, or device)

        Returns:
            Address object or None if not found
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return None

        try:
            # Use fetch method to get the address by name
            kwargs = {container_type: container}
            result = self.client.address.fetch(name=name, **kwargs)
            return result
        except Exception as e:
            logger.error(f"Error getting address by name: {e}")
            return None

    def list_addresses(
        self, container: str, container_type: str = "folder", exact_match: bool = False
    ) -> List[AddressResponseModel]:
        """List address objects in a container.

        Args:
            container: Container name (folder, snippet, or device)
            container_type: Container type (folder, snippet, or device)
            exact_match: Whether to only include addresses directly in this container

        Returns:
            List of address objects
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return []

        try:
            # Use list method to get addresses
            kwargs = {container_type: container}
            result = self.client.address.list(exact_match=exact_match, **kwargs)
            return result
        except Exception as e:
            logger.error(f"Error listing addresses: {e}")
            return []

    def delete_address(self, name: str, container: str, container_type: str) -> bool:
        """Delete an address object.

        Args:
            name: Name of the address object to delete
            container: Container name (folder, snippet, or device)
            container_type: Container type (folder, snippet, or device)

        Returns:
            True if deletion was successful, False otherwise
        """
        if self.client is None:
            logger.error("SCM client not initialized")
            return False

        try:
            # Get the address by name first
            address = self.get_address_by_name(name, container, container_type)
            if not address:
                logger.error(f"Address not found: {name}")
                return False

            # Delete the address using its ID
            self.client.address.delete(str(address.id))
            logger.info(f"Deleted address: {name}")
            return True
        except Exception as e:
            logger.error(f"Error deleting address: {e}")
            return False

    def commit(self, folders: List[str], description: str = "CICD automated commit", sync: bool = True) -> Dict[str, Any]:
        """Commit changes to SCM.

        Args:
            folders: List of folders to commit
            description: Commit description
            sync: Whether to wait for commit to complete

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

            if status == "SUCCESS" or job_id:
                logger.info(f"Commit successful with job ID: {job_id}")
            else:
                logger.warning(f"Commit status: {status}")

            return result_dict
        except Exception as e:
            logger.error(f"Error committing changes: {str(e)}")
            return {"status": "FAILED", "error": str(e)}

    def apply_addresses_from_file(self, file_path: Union[str, Path], commit_changes: bool = False) -> bool:
        """Apply address objects from a configuration file.

        This method handles the create or update decision based on whether the address exists.

        Args:
            file_path: Path to the address configuration file
            commit_changes: Whether to commit changes after applying addresses

        Returns:
            True if all addresses were applied successfully, False otherwise
        """
        # Load and validate addresses
        addresses = self.load_addresses_from_file(file_path)
        if not addresses:
            logger.error("No valid addresses found in configuration file")
            return False

        if self.client is None:
            logger.error("SCM client not initialized")
            return False

        # Apply the addresses
        success, affected_folders = self._apply_addresses(addresses)

        # Commit changes if requested and there are affected folders
        if commit_changes and affected_folders and success:
            # Check both the status and look for job_id to determine success
            # The SDK sometimes returns None for status even when commit is successful
            commit_result = self.commit(list(affected_folders))
            status = commit_result.get("status")
            job_id = commit_result.get("job_id")

            if job_id and (status == "SUCCESS" or status is None):
                logger.info(f"Commit successful with job ID: {job_id}")
            else:
                logger.warning(f"Commit may have failed. Status: {status}")
                success = False

        return success

    def _apply_addresses(self, addresses: List[AddressCreateModel]) -> tuple[bool, set[str]]:
        """Apply a list of address objects.

        Args:
            addresses: List of address objects to apply

        Returns:
            Tuple of (success, affected_folders)
        """
        success = True
        affected_folders = set()

        # Group addresses by container to minimize API calls
        container_addresses = {}
        for address in addresses:
            # Get container info
            container_info = self._get_container_info(address)
            if not container_info:
                logger.error(f"No container specified for address: {address.name}")
                success = False
                continue

            container, container_type = container_info

            # Track folder for commits
            if container_type == "folder":
                affected_folders.add(container)

            # Group by container and type
            key = (container, container_type)
            if key not in container_addresses:
                container_addresses[key] = []
            container_addresses[key].append(address)

        # Process addresses by container
        for (container, container_type), container_address_list in container_addresses.items():
            # Get existing addresses in this container
            existing_addresses = self.list_addresses(container, container_type=container_type, exact_match=True)

            # Create a lookup map for faster access
            existing_address_map = {address.name: address for address in existing_addresses}

            # Apply each address
            for address in container_address_list:
                result = self._apply_single_address_with_lookup(address, container, container_type, existing_address_map)
                if not result:
                    success = False

        return success, affected_folders

    def _get_container_info(self, address: AddressCreateModel) -> Optional[tuple[str, str]]:
        """Extract container information from an address.

        Args:
            address: Address object

        Returns:
            Tuple of (container, container_type) or None if no container is specified
        """
        container = None
        container_type = None

        if address.folder:
            container = address.folder
            container_type = "folder"
        elif address.snippet:
            container = address.snippet
            container_type = "snippet"
        elif address.device:
            container = address.device
            container_type = "device"
        else:
            return None

        return container, container_type

    def _apply_single_address_with_lookup(
        self, address: AddressCreateModel, container: str, container_type: str, existing_address_map: dict
    ) -> bool:
        """Apply a single address object using a lookup of existing addresses.

        Args:
            address: Address object to apply
            container: Container name
            container_type: Container type (folder, snippet, or device)
            existing_address_map: Dictionary mapping address names to existing address objects

        Returns:
            True if the address was applied successfully, False otherwise
        """
        try:
            # Check if the address exists in our lookup map
            if address.name in existing_address_map:
                # Get the existing address with its ID
                existing_address = existing_address_map[address.name]

                # For updating, we need to create a separate update model with the ID
                update_data = address.model_dump(exclude_none=True)

                # Make sure to set the ID field for the update
                update_data["id"] = existing_address.id

                # Create an update model and update the address
                logger.info(f"Updating existing address: {address.name}")
                update_model = AddressUpdateModel(**update_data)
                result = self.update_address(update_model)
            else:
                # Create a new address
                logger.info(f"Creating new address: {address.name}")
                result = self.create_address(address)

            return result is not None
        except Exception as e:
            logger.error(f"Error applying address {address.name}: {str(e)}")
            return False
