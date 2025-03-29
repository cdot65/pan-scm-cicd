"""
Configuration module for the SCM CICD pipeline.

This module initializes the Dynaconf settings object for the application.
"""

from pathlib import Path

from dynaconf import Dynaconf

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Initialize Dynaconf with the settings files
settings = Dynaconf(
    envvar_prefix="SCM",
    settings_files=[
        PROJECT_ROOT / "settings.yaml",
        PROJECT_ROOT / ".secrets.yaml",
    ],
    environments=True,  # Enable different environments like development, production
    load_dotenv=True,  # Load environment variables from .env file
    env_switcher="ENV_FOR_DYNACONF",  # Environment switcher variable
    merge_enabled=False,  # Don't automatically merge nested dictionaries
)

# Validate required settings (uncomment and customize as needed)
# settings.validators.register(
#     Validator("CLIENT_ID", must_exist=True),
#     Validator("CLIENT_SECRET", must_exist=True),
#     Validator("TSG_ID", must_exist=True),
# )

# settings.validators.validate()
