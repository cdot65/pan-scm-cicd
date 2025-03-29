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
                console.print(f"  - [cyan]{rule.name}[/cyan] in [yellow]{rule.folder or rule.snippet or rule.device}[/yellow]")
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
    rulebase: str = RULEBASE_ARG,
):
    """List security rules in a container."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print(f"[bold green]Listing rules in[/bold green] [cyan]{container}[/cyan]")
    rules = manager.list_rules(container, rulebase=rulebase)

    if not rules:
        console.print(f"[yellow]No rules found in {container}[/yellow]")
        return

    # Create a table
    table = Table(title=f"Security Rules in {container}")
    table.add_column("Name", style="cyan")
    table.add_column("Source", style="green")
    table.add_column("Destination", style="green")
    table.add_column("Application", style="yellow")
    table.add_column("Service", style="yellow")
    table.add_column("Action", style="red")

    for rule in rules:
        # Get values safely with dict.get() for both dictionary and model objects
        def safe_get(obj, attr, default=""):
            if isinstance(obj, dict):
                return obj.get(attr, default)
            else:
                return getattr(obj, attr, default)

        def format_list(items, max_items=3):
            if not items:
                return "any"
            items_to_show = items[:max_items]
            ellipsis = "..." if len(items) > max_items else ""
            return ", ".join(items_to_show) + ellipsis

        name = safe_get(rule, "name")
        source = format_list(safe_get(rule, "source", ["any"]))
        destination = format_list(safe_get(rule, "destination", ["any"]))
        application = format_list(safe_get(rule, "application", ["any"]))
        service = format_list(safe_get(rule, "service", ["any"]))
        action = safe_get(rule, "action", "allow")

        table.add_row(name, source, destination, application, service, action)

    console.print(table)


@app.command()
def delete(
    name: str = NAME_ARG,
    container: str = CONTAINER_ARG,
    rulebase: str = RULEBASE_ARG,
    commit: bool = COMMIT_ARG,
):
    """Delete a security rule."""
    manager = SCMSecurityRuleManager(testing=True)

    console.print(f"[bold yellow]Deleting rule[/bold yellow] [cyan]{name}[/cyan] from [cyan]{container}[/cyan]")
    success = manager.delete_rule(name, container, rulebase=rulebase)

    if success and commit:
        console.print("Committing changes...")
        commit_result = manager.commit([container], description=f"Delete rule {name} via CICD")
        if not commit_result.get("status") == "SUCCESS":
            console.print(f"[bold red]Commit failed: {commit_result.get('error', 'Unknown error')}[/bold red]")
            raise typer.Exit(code=1)

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

    console.print(f"[bold yellow]Committing changes to folders:[/bold yellow] {', '.join(folders)}")
    result = manager.commit(folders, description=description)

    if result.get("status") == "SUCCESS":
        console.print(f"[bold green]Commit successful:[/bold green] {result.get('job_id')}")
    else:
        console.print(f"[bold red]Commit failed:[/bold red] {result.get('status')}")
        console.print(f"Error: {result.get('error', 'Unknown error')}")
        raise typer.Exit(code=1)


def main():
    """Main entry point for the CLI."""
    try:
        app()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
