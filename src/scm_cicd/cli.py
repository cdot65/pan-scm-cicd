"""
Command-line interface for SCM CICD Security Rules Manager.

This module provides a CLI interface for managing security rules in Palo Alto Networks
Strata Cloud Manager through a CICD pipeline.
"""

import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from scm_cicd.security_rules import SCMSecurityRuleManager

console = Console()
app = typer.Typer(help="SCM CICD Security Rules Manager")

# Define common arguments as module level variables
CONFIG_FILE_ARG = typer.Argument(..., help="Path to the security rule configuration file (JSON or YAML)", exists=True)
CONTAINER_ARG = typer.Argument(..., help="Container name (folder, snippet, or device)")
CONTAINER_TYPE_ARG = typer.Option("folder", "--type", "-t", help="Container type (folder, snippet, or device)")
RULEBASE_ARG = typer.Option("pre", "--rulebase", "-r", help="Rulebase to apply rules to (pre or post)")
COMMIT_ARG = typer.Option(False, "--commit", "-c", help="Commit changes after applying rules")
DRY_RUN_ARG = typer.Option(False, "--dry-run", "-d", help="Validate the rule configuration without applying changes")
NAME_ARG = typer.Argument(..., help="Rule name")
DESCRIPTION_ARG = typer.Option("CICD automated commit", "--message", "-m", help="Commit description")
FOLDERS_ARG = typer.Argument(..., help="Folders to commit")


@app.command()
def apply(
    config_file: Optional[Path] = CONFIG_FILE_ARG,
    rulebase: str = RULEBASE_ARG,
    commit: bool = COMMIT_ARG,
    dry_run: bool = DRY_RUN_ARG,
):
    """Apply security rules from a configuration file."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print(f"[bold green]Applying rules from[/bold green] [cyan]{config_file}[/cyan]")

    if dry_run:
        # Just load and validate the rules without applying
        rules = manager.load_rules_from_file(config_file)
        if rules:
            console.print(f"[bold green]Configuration valid - found {len(rules)} rules[/bold green]")
            for rule in rules:
                container_type = "unknown"
                container_value = None
                if rule.folder:
                    container_type = "folder"
                    container_value = rule.folder
                elif rule.snippet:
                    container_type = "snippet"
                    container_value = rule.snippet
                elif rule.device:
                    container_type = "device"
                    container_value = rule.device

                console.print(f"  - [cyan]{rule.name}[/cyan] in [yellow]{container_type}:{container_value}[/yellow]")
            return
        else:
            console.print("[bold red]Invalid configuration[/bold red]")
            raise typer.Exit(code=1)

    success = manager.apply_rules_from_file(config_file, rulebase=rulebase, commit_changes=commit)

    if success:
        console.print("[bold green]Successfully applied all rules[/bold green]")
    else:
        console.print("[bold red]Failed to apply some or all rules[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def list(
    container: Optional[str] = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_ARG,
    rulebase: str = RULEBASE_ARG,
):
    """List security rules in a container."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print(f"[bold green]Listing rules in[/bold green] [cyan]{container_type}:{container}[/cyan]")
    rules = manager.list_rules(container, container_type=container_type, rulebase=rulebase)

    if not rules:
        console.print(f"[yellow]No rules found in {container_type}:{container}[/yellow]")
        return

    # Create a table
    table = Table(title=f"Security Rules in {container_type}:{container}")
    table.add_column("Name", style="cyan")
    table.add_column("Source", style="green")
    table.add_column("Destination", style="green")
    table.add_column("Application", style="yellow")
    table.add_column("Service", style="yellow")
    table.add_column("Action", style="red")

    for rule in rules:

        def format_list(items, max_items=3):
            if not items:
                return "any"
            items_to_show = items[:max_items]
            ellipsis = "..." if len(items) > max_items else ""
            return ", ".join(items_to_show) + ellipsis

        name = rule.name
        source = format_list(rule.source if hasattr(rule, "source") and rule.source else ["any"])
        destination = format_list(rule.destination if hasattr(rule, "destination") and rule.destination else ["any"])
        application = format_list(rule.application if hasattr(rule, "application") and rule.application else ["any"])
        service = format_list(rule.service if hasattr(rule, "service") and rule.service else ["any"])
        action = rule.action if hasattr(rule, "action") and rule.action else "allow"

        table.add_row(name, source, destination, application, service, action)

    console.print(table)


@app.command()
def list_exact(
    container: Optional[str] = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_ARG,
    rulebase: str = RULEBASE_ARG,
):
    """List only security rules defined directly in a container (excludes inherited rules)."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print(f"[bold green]Listing directly defined rules in[/bold green] [cyan]{container_type}:{container}[/cyan]")
    rules = manager.list_rules(container, container_type=container_type, rulebase=rulebase, exact_match=True)

    if not rules:
        console.print(f"[yellow]No directly defined rules found in {container_type}:{container}[/yellow]")
        return

    # Create a table
    table = Table(title=f"Security Rules Defined Directly in {container_type}:{container}")
    table.add_column("Name", style="cyan")
    table.add_column("Container", style="magenta")
    table.add_column("Source", style="green")
    table.add_column("Destination", style="green")
    table.add_column("Application", style="yellow")
    table.add_column("Service", style="yellow")
    table.add_column("Action", style="red")

    for rule in rules:

        def format_list(items, max_items=3):
            if not items:
                return "any"
            items_to_show = items[:max_items]
            ellipsis = "..." if len(items) > max_items else ""
            return ", ".join(items_to_show) + ellipsis

        # Get the container value based on what's present
        container_value = "Unknown"
        if rule.folder:
            container_value = f"folder:{rule.folder}"
        elif rule.snippet:
            container_value = f"snippet:{rule.snippet}"
        elif rule.device:
            container_value = f"device:{rule.device}"

        name = rule.name
        source = format_list(rule.source if hasattr(rule, "source") and rule.source else ["any"])
        destination = format_list(rule.destination if hasattr(rule, "destination") and rule.destination else ["any"])
        application = format_list(rule.application if hasattr(rule, "application") and rule.application else ["any"])
        service = format_list(rule.service if hasattr(rule, "service") and rule.service else ["any"])
        action = rule.action if hasattr(rule, "action") and rule.action else "allow"

        table.add_row(name, container_value, source, destination, application, service, action)

    console.print(table)


@app.command()
def delete(
    name: str = NAME_ARG,
    container: str = CONTAINER_ARG,
    container_type: str = CONTAINER_TYPE_ARG,
    rulebase: str = RULEBASE_ARG,
    commit: bool = COMMIT_ARG,
):
    """Delete a security rule."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print(
        f"[bold yellow]Deleting rule[/bold yellow] [cyan]{name}[/cyan] from [cyan]{container_type}:{container}[/cyan]"
    )
    success = manager.delete_rule(name, container, container_type=container_type, rulebase=rulebase)

    if success and commit and container_type == "folder":
        console.print("Committing changes...")
        commit_result = manager.commit([container], description=f"Delete rule {name} via CICD")
        if not commit_result.get("status") == "SUCCESS":
            console.print(f"[bold red]Commit failed: {commit_result.get('error', 'Unknown error')}[/bold red]")
            raise typer.Exit(code=1)
    elif success and commit and container_type != "folder":
        console.print("[bold yellow]Note:[/bold yellow] Commit is only supported for folder containers. Skipping commit.")

    if success:
        console.print(f"[bold green]Successfully deleted rule {name}[/bold green]")
    else:
        console.print(f"[bold red]Failed to delete rule {name}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def commit(
    folders: List[str] = FOLDERS_ARG,
    description: str = DESCRIPTION_ARG,
):
    """Commit changes to SCM."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print("[bold green]Committing changes to folders:[/bold green]")
    for folder in folders:
        console.print(f"  - [cyan]{folder}[/cyan]")

    result = manager.commit(folders, description=description)
    status = result.get("status", "UNKNOWN")
    job_id = result.get("job_id", "N/A")

    if status == "SUCCESS":
        console.print(f"[bold green]Commit successful. Job ID: {job_id}[/bold green]")
    else:
        console.print(f"[bold red]Commit failed: {result.get('error', 'Unknown error')}[/bold red]")
        console.print(f"Status: {status}")
        raise typer.Exit(code=1)


def main():
    """Main entry point for the CLI."""
    try:
        app()
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
