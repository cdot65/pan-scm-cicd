# SCM-CLI: Understanding the Architecture of a Typer CLI Application

This educational guide explains how the `scm-cli` application is constructed, focusing on how its components work together to create a powerful command-line interface for managing Palo Alto Networks Strata Cloud Manager (SCM) security policies.

## Project Overview

The `scm-cli` is a command-line interface (CLI) tool built with Python's Typer framework that allows security engineers to manage security policies in Palo Alto Networks Strata Cloud Manager. It leverages the `pan-scm-sdk` Python library to interact with the SCM API, providing a streamlined interface for common security policy management tasks.

Key features include:
- Creating and applying security rules from configuration files
- Listing existing security rules in containers (folders, snippets, or devices)
- Deleting security rules
- Committing changes to SCM

## Code Structure and Architecture

The application follows a modular design pattern with clear separation of concerns:

```
src/scm_cicd/
├── __init__.py       # Package initialization
├── cli.py            # Command-line interface definitions using Typer
├── config.py         # Configuration management using Dynaconf
└── security_rules.py # Core business logic for SCM security rule operations
```

### How the Components Work Together

Here's a high-level flow of how the application works:

1. The user invokes the CLI with a command (`scm-cli apply`, `scm-cli list`, etc.)
2. The `cli.py` module processes command-line arguments using Typer
3. The CLI module instantiates the `SCMSecurityRuleManager` from `security_rules.py`
4. The manager initializes the `pan-scm-sdk` client using credentials from `config.py`
5. The manager executes the requested operation through the SDK
6. Results are formatted and displayed to the user via the CLI

Let's explore each component in detail:

## Component Deep Dive

### 1. CLI Module (`cli.py`)

The CLI module is the entry point for the application and is built using the Typer framework. Typer is a library for building CLI applications that leverages Python type hints to define command-line interfaces.

```python
# Key components of cli.py
import typer
from rich.console import Console
from scm_cicd.security_rules import SCMSecurityRuleManager

# Create the Typer app instance
app = typer.Typer(help="SCM CICD Security Rules Manager")

# Define common arguments as module-level variables for reuse
CONFIG_FILE_ARG = typer.Argument(..., help="Path to the security rule configuration file")

# Command definition using decorator pattern
@app.command()
def apply(
    config_file: Optional[Path] = CONFIG_FILE_ARG,
    rulebase: str = RULEBASE_ARG,
    commit: bool = COMMIT_ARG,
    dry_run: bool = DRY_RUN_ARG,
):
    """Apply security rules from a configuration file."""
    # Instantiate the manager
    manager = SCMSecurityRuleManager()

    # Call the appropriate method
    success = manager.apply_rules_from_file(config_file, rulebase=rulebase, commit_changes=commit)

    # Format and display results
    if success:
        console.print("[bold green]Successfully applied all rules[/bold green]")
```

**Key Concepts:**
- **Typer App**: The `app = typer.Typer()` creates the main application object
- **Command Decorators**: `@app.command()` defines CLI commands
- **Type Hints**: Python type hints define argument types and validation
- **Rich Library**: Used for formatted console output

### 2. Security Rules Manager (`security_rules.py`)

This module contains the core business logic for interacting with SCM through the `pan-scm-sdk`. It handles:
- Authentication with SCM
- Loading rule configurations from files
- Creating, updating, listing, and deleting security rules
- Committing changes to SCM

```python
# Key components of security_rules.py
from scm.client import Scm
from pydantic import BaseModel

# Pydantic model for rule configuration validation
class SecurityRuleConfig(BaseModel):
    name: str
    folder: Optional[str]
    # ... other fields

class SCMSecurityRuleManager:
    def __init__(self):
        """Initialize the SCM Security Rule Manager."""
        self.client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the SCM client with proper authentication."""
        # Get credentials from settings
        client_id = settings.get("client_id", "")
        client_secret = settings.get("client_secret", "")
        tsg_id = settings.get("tsg_id", "")

        # Initialize the SCM client from the SDK
        self.client = Scm(
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            # ... other settings
        )

    def apply_rules_from_file(self, file_path, rulebase="pre", commit_changes=False):
        """Apply security rules from a configuration file."""
        # Load rules from file
        rules = self.load_rules_from_file(file_path)

        # Process each rule
        for rule in rules:
            # Check if rule exists and create or update accordingly
            existing_rule = self.get_rule_by_name(rule.name, rule.folder, rulebase)
            if existing_rule:
                self.update_rule(rule, rulebase)
            else:
                self.create_rule(rule, rulebase)

        # Commit changes if requested
        if commit_changes:
            self.commit([rule.folder for rule in rules])
```

**Key Concepts:**
- **Pydantic Models**: Used for data validation and serialization
- **SDK Initialization**: Handles authentication with SCM
- **File Parsing**: Loads and validates rule configurations from YAML/JSON files
- **CRUD Operations**: Methods for creating, reading, updating, and deleting rules

### 3. Configuration Module (`config.py`)

The configuration module uses Dynaconf to manage application settings, including SCM credentials and API endpoints.

```python
# Key components of config.py
from dynaconf import Dynaconf

# Initialize Dynaconf with the settings files
settings = Dynaconf(
    envvar_prefix="SCM",
    settings_files=[
        PROJECT_ROOT / "settings.yaml",
        PROJECT_ROOT / ".secrets.yaml",
    ],
    environments=True,
    load_dotenv=True,
)
```

**Key Concepts:**
- **Dynaconf**: Manages configuration from multiple sources (files, environment variables)
- **Settings Files**: Loads settings from YAML files
- **Environment Variables**: Can override settings with environment variables
- **Secret Management**: Separates sensitive credentials from regular settings

## How It All Works Together: A Walkthrough

Let's walk through a complete example of how the application processes a command:

### Example: `scm-cli apply config/rules.yaml --commit`

1. **Command Parsing**:
   - The `main()` function in `cli.py` calls `app()`, which parses the command line arguments
   - Typer identifies the `apply` command and its arguments

2. **Manager Initialization**:
   - The `apply()` function creates an instance of `SCMSecurityRuleManager`
   - During initialization, the manager loads credentials from the configuration
   - The manager initializes the SCM SDK client with these credentials

3. **Rule Processing**:
   - The manager loads and validates rules from the YAML file using Pydantic models
   - For each rule, it checks if the rule already exists in SCM
   - It creates new rules or updates existing ones as needed

4. **Committing Changes**:
   - Since the `--commit` flag was provided, the manager commits the changes to SCM
   - The commit operation is performed through the SDK

5. **Result Presentation**:
   - The CLI module formats the results using Rich and displays them to the user
   - Success or failure messages are shown with appropriate formatting

## Key Design Patterns and Concepts

The application demonstrates several important software design patterns and concepts:

1. **Command Pattern**: The CLI commands encapsulate operations as objects
2. **Facade Pattern**: The `SCMSecurityRuleManager` provides a simplified interface to the complex SCM SDK
3. **Dependency Injection**: The manager is injected into the CLI commands
4. **Data Validation**: Pydantic models ensure data integrity
5. **Separation of Concerns**: Clear boundaries between UI (CLI), business logic (manager), and data access (SDK)

## Extending the CLI

To add a new command to the CLI, you would:

1. Define a new function in `cli.py` with the `@app.command()` decorator
2. Add appropriate type-hinted parameters for command arguments
3. Implement the business logic in `security_rules.py` as needed
4. Call the business logic from your command function
5. Format and display results to the user

Example of adding a new command:

```python
@app.command()
def export(
    container: str = CONTAINER_ARG,
    output_file: Path = typer.Argument(..., help="Output file path"),
    rulebase: str = RULEBASE_ARG,
):
    """Export security rules from a container to a file."""
    manager = SCMSecurityRuleManager()

    console.print(f"[bold green]Exporting rules from[/bold green] [cyan]{container}[/cyan]")
    rules = manager.list_rules(container, rulebase=rulebase)

    # Add export functionality to the manager
    success = manager.export_rules_to_file(rules, output_file)

    if success:
        console.print(f"[bold green]Successfully exported rules to {output_file}[/bold green]")
    else:
        console.print(f"[bold red]Failed to export rules[/bold red]")
        raise typer.Exit(code=1)
```

## Conclusion

The `scm-cli` application demonstrates a well-structured approach to building command-line tools with Python. By leveraging Typer for the CLI interface, Pydantic for data validation, and the `pan-scm-sdk` for SCM interactions, it provides a robust and maintainable solution for managing security policies.

Key takeaways:
- Typer simplifies CLI development with Python type hints
- Pydantic ensures data validation and serialization
- Clear separation of concerns makes the code maintainable
- The facade pattern simplifies complex SDK interactions
- Rich formatting enhances the user experience

This architecture can serve as a template for building other CLI tools that interact with APIs, especially those requiring complex data validation and formatting.
