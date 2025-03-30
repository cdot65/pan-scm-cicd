"""
Command Line Interface for managing Palo Alto Networks Strata Cloud Manager through a CICD pipeline.
"""

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from scm_cicd.address import SCMAddressManager
from scm_cicd.security_rules import SCMSecurityRuleManager

console = Console()
app = typer.Typer(help="SCM CICD Manager for Palo Alto Networks Strata Cloud Manager")

# Create subcommands for different operations
apply_app = typer.Typer(help="Apply configuration to SCM")
list_app = typer.Typer(help="List objects from SCM")
delete_app = typer.Typer(help="Delete objects from SCM")

# Register the subcommand apps
app.add_typer(apply_app, name="apply")
app.add_typer(list_app, name="list")
app.add_typer(delete_app, name="delete")

# Define common arguments as module level variables
CONFIG_FILE_ARG = typer.Argument(..., help="Path to the configuration file (JSON or YAML)", exists=True)
CONTAINER_ARG = typer.Argument(..., help="Container name (folder, snippet, or device)")
CONTAINER_TYPE_OPT = typer.Option("folder", "--type", "-t", help="Container type: folder, snippet, or device")
RULEBASE_OPT = typer.Option("pre", "--rulebase", "-r", help="Rulebase to use: pre or post")
COMMIT_OPT = typer.Option(False, "--commit", "-c", help="Commit changes after operation")
DRY_RUN_OPT = typer.Option(False, "--dry-run", "-d", help="Validate but don't apply changes")

#
# Security Rules Implementation
#


@apply_app.command("security-rule")
def apply_security_rule(
    file_path: Path = CONFIG_FILE_ARG,
    rulebase: str = RULEBASE_OPT,
    commit: bool = COMMIT_OPT,
    dry_run: bool = DRY_RUN_OPT,
):
    """Apply security rules from a configuration file."""
    manager = SCMSecurityRuleManager()
    console.print(f"Applying rules from {file_path}")

    if dry_run:
        # Only validate the configuration
        rules = manager.load_rules_from_file(file_path)
        if not rules:
            console.print("Failed to load rules", style="bold red")
            sys.exit(1)
        console.print("Configuration validated successfully", style="bold green")
        return

    success = manager.apply_rules_from_file(file_path, rulebase, commit)
    if success:
        console.print("Successfully applied all rules", style="bold green")
    else:
        console.print("Failed to apply some or all rules", style="bold red")
        sys.exit(1)


@list_app.command("security-rule")
def list_security_rules(
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_OPT,
    rulebase: str = RULEBASE_OPT,
):
    """List security rules from a container."""
    manager = SCMSecurityRuleManager()
    rules = manager.list_rules(container, container_type, rulebase)

    if not rules:
        console.print(f"No rules found in {container_type} '{container}'", style="yellow")
        return

    # Create a table for displaying rules
    table = Table(title=f"Security Rules in {container_type.capitalize()} '{container}'")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Action", style="green" if rulebase == "pre" else "red")

    for rule in rules:
        table.add_row(
            rule.name,
            rule.description or "",
            ", ".join(rule.source) if hasattr(rule, "source") else "",
            ", ".join(rule.destination) if hasattr(rule, "destination") else "",
            rule.action if hasattr(rule, "action") else "",
        )

    console.print(table)


@delete_app.command("security-rule")
def delete_security_rule(
    rule_name: str = typer.Argument(..., help="Name of the rule to delete"),
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_OPT,
    rulebase: str = RULEBASE_OPT,
    commit: bool = COMMIT_OPT,
):
    """Delete a security rule from a container."""
    manager = SCMSecurityRuleManager()
    success = manager.delete_rule(rule_name, container, container_type, rulebase)

    if success:
        console.print(f"Successfully deleted rule '{rule_name}'", style="bold green")

        if commit:
            result = manager.commit([container])
            if result.get("status") == "SUCCESS" or result.get("job_id"):
                console.print("Changes committed successfully", style="bold green")
            else:
                console.print("Failed to commit changes", style="bold red")
                sys.exit(1)
    else:
        console.print(f"Failed to delete rule '{rule_name}'", style="bold red")
        sys.exit(1)


#
# Address Objects Implementation
#


@apply_app.command("address")
def apply_address(
    file_path: Path = CONFIG_FILE_ARG,
    commit: bool = COMMIT_OPT,
    dry_run: bool = DRY_RUN_OPT,
):
    """Apply address objects from a configuration file."""
    manager = SCMAddressManager()
    console.print(f"Applying address objects from {file_path}")

    if dry_run:
        # Only validate the configuration
        addresses = manager.load_addresses_from_file(file_path)
        if not addresses:
            console.print("Failed to load address objects", style="bold red")
            sys.exit(1)
        console.print("Configuration validated successfully", style="bold green")
        console.print(f"Found {len(addresses)} valid address objects:")
        for addr in addresses:
            container_type = "unknown"
            container_name = "unknown"
            if addr.folder:
                container_type = "folder"
                container_name = addr.folder
            elif addr.snippet:
                container_type = "snippet"
                container_name = addr.snippet
            elif addr.device:
                container_type = "device"
                container_name = addr.device

            console.print(f"  - {addr.name} in {container_type}:{container_name}")
        return

    success = manager.apply_addresses_from_file(file_path, commit)
    if success:
        console.print("Successfully applied all address objects", style="bold green")
    else:
        console.print("Failed to apply some or all address objects", style="bold red")
        sys.exit(1)


@list_app.command("address")
def list_addresses(
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_OPT,
    exact_match: bool = typer.Option(False, "--exact", help="Only show objects defined directly in this container"),
):
    """List address objects from a container."""
    manager = SCMAddressManager()
    addresses = manager.list_addresses(container, container_type, exact_match)

    if not addresses:
        console.print(f"No address objects found in {container_type} '{container}'", style="yellow")
        return

    # Create a table for displaying addresses
    table = Table(title=f"Address Objects in {container_type.capitalize()} '{container}'")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Value", style="green")
    table.add_column("Description")
    table.add_column("Tags")

    for addr in addresses:
        # Determine address type and value
        addr_type = "Unknown"
        addr_value = ""

        if addr.ip_netmask:
            addr_type = "IP/Netmask"
            addr_value = addr.ip_netmask
        elif addr.ip_range:
            addr_type = "IP Range"
            addr_value = addr.ip_range
        elif addr.ip_wildcard:
            addr_type = "IP Wildcard"
            addr_value = addr.ip_wildcard
        elif addr.fqdn:
            addr_type = "FQDN"
            addr_value = addr.fqdn

        table.add_row(addr.name, addr_type, addr_value, addr.description or "", ", ".join(addr.tag) if addr.tag else "")

    console.print(table)


@delete_app.command("address")
def delete_address(
    address_name: str = typer.Argument(..., help="Name of the address object to delete"),
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_OPT,
    commit: bool = COMMIT_OPT,
):
    """Delete an address object from a container."""
    manager = SCMAddressManager()
    success = manager.delete_address(address_name, container, container_type)

    if success:
        console.print(f"Successfully deleted address object '{address_name}'", style="bold green")

        if commit and container_type == "folder":
            result = manager.commit([container])
            if result.get("status") == "SUCCESS" or result.get("job_id"):
                console.print("Changes committed successfully", style="bold green")
            else:
                console.print("Failed to commit changes", style="bold red")
                sys.exit(1)
        elif commit and container_type != "folder":
            console.print("Commit is only supported for folder containers", style="yellow")
    else:
        console.print(f"Failed to delete address object '{address_name}'", style="bold red")
        sys.exit(1)


#
# Backward compatibility commands
#


@app.command("apply")
def apply_legacy(
    file_path: Path = CONFIG_FILE_ARG,
    rulebase: str = RULEBASE_OPT,
    commit: bool = COMMIT_OPT,
    dry_run: bool = DRY_RUN_OPT,
):
    """
    [Deprecated] Apply configuration from a file.

    Use 'scm-cicd apply security-rule' instead.
    """
    console.print("[yellow]Warning: This command is deprecated. Use 'scm-cicd apply security-rule' instead.[/yellow]")
    apply_security_rule(file_path, rulebase, commit, dry_run)


@app.command("list")
def list_legacy(
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_OPT,
    rulebase: str = RULEBASE_OPT,
):
    """
    [Deprecated] List rules from a container.

    Use 'scm-cicd list security-rule' instead.
    """
    console.print("[yellow]Warning: This command is deprecated. Use 'scm-cicd list security-rule' instead.[/yellow]")
    list_security_rules(container, container_type, rulebase)


@app.command("delete")
def delete_legacy(
    rule_name: str = typer.Argument(..., help="Name of the rule to delete"),
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_OPT,
    rulebase: str = RULEBASE_OPT,
    commit: bool = COMMIT_OPT,
):
    """
    [Deprecated] Delete a rule from a container.

    Use 'scm-cicd delete security-rule' instead.
    """
    console.print("[yellow]Warning: This command is deprecated. Use 'scm-cicd delete security-rule' instead.[/yellow]")
    delete_security_rule(rule_name, container, container_type, rulebase, commit)


#
# Main CLI entry point
#

if __name__ == "__main__":
    app()
