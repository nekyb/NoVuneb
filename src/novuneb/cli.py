"""
Command-line interface for NoVuneb security scanner.
"""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from novuneb.core.config import Config, RuntimeConfig, load_config
from novuneb.core.engine import ScanEngine
from novuneb.core.models import Severity
from novuneb.reporters.html_reporter import HTMLReporter
from novuneb.reporters.json_reporter import JSONReporter
from novuneb.reporters.sarif_reporter import SARIFReporter
from novuneb.utils.logger import setup_logger

app = typer.Typer(
    name="novuneb",
    help="Advanced vulnerability detection and auto-fixing security tool",
    add_completion=False,
)

console = Console()


def print_banner() -> None:
    """Print NoVuneb banner"""
    banner = """
[bold magenta]
███╗   ██╗ ██████╗ ██╗   ██╗██╗   ██╗███╗   ██╗███████╗██████╗ 
████╗  ██║██╔═══██╗██║   ██║██║   ██║████╗  ██║██╔════╝██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║██║   ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╗██║██║   ██║╚██╗ ██╔╝██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚████║╚██████╔╝ ╚████╔╝ ╚██████╔╝██║ ╚████║███████╗██████╔╝
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═════╝ 
[/bold magenta]
[cyan]Advanced Vulnerability Detection & Auto-Fixing Tool v1.0.0[/cyan]
[dim]Securing your code, one vulnerability at a time[/dim]
    """
    console.print(banner)


@app.command(name="scan")
def scan_command(
    target: Path = typer.Argument(
        ...,
        help="Path to scan (file or directory)",
        exists=True,
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Report format (json, html, sarif)",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--min-severity",
        "-s",
        help="Minimum severity level (critical, high, medium, low, info)",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Enable automated fixes",
    ),
    languages: Optional[str] = typer.Option(
        None,
        "--languages",
        "-l",
        help="Comma-separated list of languages to scan",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
) -> None:
    """
    Scan target path for security vulnerabilities.
    
    Examples:
    
        novuneb scan ./project
        
        novuneb scan ./project --fix --format html
        
        novuneb scan ./project --min-severity high --output report.json
    """
    print_banner()
    
    setup_logger(verbose=verbose)
    
    config = load_config(config_file)
    
    if severity:
        config.scan.severity_threshold = severity
    
    if fix:
        config.autofix.enabled = True
    
    if languages:
        config.scan.languages = [lang.strip() for lang in languages.split(",")]
    
    runtime_config = RuntimeConfig(
        config=config,
        target_path=target,
        output_file=output,
        verbose=verbose,
    )
    
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Languages:[/bold] {', '.join(config.scan.languages)}\n"
            f"[bold]Severity Threshold:[/bold] {config.scan.severity_threshold}\n"
            f"[bold]Auto-Fix:[/bold] {'Enabled' if config.autofix.enabled else 'Disabled'}",
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
        )
    )
    
    engine = ScanEngine(runtime_config)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        
        result = engine.scan_path(target)
        
        progress.update(task, completed=True, description="✓ Scan completed")
    
    display_results(result)
    
    if output or format:
        output_path = output or Path(f"novuneb-report.{format}")
        
        if format == "html":
            reporter = HTMLReporter(output_path)
        elif format == "sarif":
            reporter = SARIFReporter(output_path)
        else:
            reporter = JSONReporter(output_path)
        
        reporter.generate(result)
        console.print(f"\n[green]✓[/green] Report saved to: [bold]{output_path}[/bold]")
    
    if result.statistics.critical_count > 0 or result.statistics.high_count > 0:
        sys.exit(1)


@app.command(name="scan-github")
def scan_github_command(
    repo: str = typer.Argument(
        ...,
        help="GitHub repository (owner/repo)",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        "-t",
        help="GitHub API token",
        envvar="GITHUB_TOKEN",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Report format",
    ),
) -> None:
    """
    Scan a GitHub repository.
    
    Example:
    
        novuneb scan-github owner/repo --token YOUR_TOKEN
    """
    print_banner()
    
    if not token:
        console.print("[red]Error:[/red] GitHub token is required")
        sys.exit(1)
    
    setup_logger()
    
    config = load_config()
    config.github.token = token
    config.github.enabled = True
    
    runtime_config = RuntimeConfig(
        config=config,
        target_path=Path("."),
        output_file=output,
    )
    
    console.print(f"[cyan]Cloning and scanning repository:[/cyan] [bold]{repo}[/bold]")
    
    engine = ScanEngine(runtime_config)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning repository...", total=None)
        
        result = engine.scan_git_repository(f"https://github.com/{repo}.git")
        
        progress.update(task, completed=True)
    
    display_results(result)


@app.command(name="version")
def version_command() -> None:
    """Display NoVuneb version information"""
    from novuneb import __version__
    
    console.print(
        Panel(
            f"[bold cyan]NoVuneb[/bold cyan] v{__version__}\n\n"
            "Advanced Vulnerability Detection & Auto-Fixing Tool\n"
            "License: MIT\n"
            "Homepage: https://github.com/novuneb/novuneb",
            border_style="cyan",
        )
    )


@app.command(name="config")
def config_command(
    show: bool = typer.Option(
        False,
        "--show",
        help="Show current configuration",
    ),
    init: bool = typer.Option(
        False,
        "--init",
        help="Initialize default configuration file",
    ),
) -> None:
    """Manage NoVuneb configuration"""
    if init:
        config_path = Path(".novuneb.yaml")
        if config_path.exists():
            console.print(
                "[yellow]Warning:[/yellow] Configuration file already exists"
            )
            return
        
        config = Config()
        config.to_file(config_path)
        console.print(
            f"[green]✓[/green] Configuration file created: [bold]{config_path}[/bold]"
        )
    
    if show:
        config = load_config()
        console.print(
            Panel(
                f"[bold]Version:[/bold] {config.version}\n"
                f"[bold]Languages:[/bold] {', '.join(config.scan.languages)}\n"
                f"[bold]Severity Threshold:[/bold] {config.scan.severity_threshold}\n"
                f"[bold]Auto-Fix:[/bold] {'Enabled' if config.autofix.enabled else 'Disabled'}\n"
                f"[bold]GitHub Integration:[/bold] {'Enabled' if config.github.enabled else 'Disabled'}",
                title="[bold cyan]Current Configuration[/bold cyan]",
                border_style="cyan",
            )
        )


def display_results(result) -> None:
    """Display scan results in rich format"""
    stats = result.statistics
    
    stats_table = Table(
        title="📊 Scan Statistics",
        show_header=True,
        header_style="bold cyan",
    )
    
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", justify="right", style="yellow")
    
    stats_table.add_row("Total Files", str(stats.total_files))
    stats_table.add_row("Total Lines", str(stats.total_lines))
    stats_table.add_row("Total Vulnerabilities", str(stats.total_vulnerabilities))
    stats_table.add_row("Critical", f"[red]{stats.critical_count}[/red]")
    stats_table.add_row("High", f"[bright_red]{stats.high_count}[/bright_red]")
    stats_table.add_row("Medium", f"[yellow]{stats.medium_count}[/yellow]")
    stats_table.add_row("Low", f"[green]{stats.low_count}[/green]")
    stats_table.add_row("Info", f"[blue]{stats.info_count}[/blue]")
    stats_table.add_row("Fixed", f"[green]{stats.fixed_count}[/green]")
    stats_table.add_row("Scan Duration", f"{stats.scan_duration:.2f}s")
    
    console.print("\n")
    console.print(stats_table)
    console.print("\n")
    
    if result.vulnerabilities:
        console.print("[bold red]⚠️  Vulnerabilities Detected[/bold red]\n")
        
        for vuln in result.get_critical_and_high()[:10]:
            severity_emoji = vuln.severity.to_emoji()
            console.print(
                f"{severity_emoji} [bold]{vuln.title}[/bold] "
                f"([{vuln.severity.value}]{vuln.severity.value.upper()}[/{vuln.severity.value}])"
            )
            console.print(f"   [dim]{vuln.location}[/dim]")
            console.print(f"   {vuln.message}\n")
    else:
        console.print(
            "[bold green]✅ No vulnerabilities detected![/bold green]"
        )


def main() -> None:
    """Main entry point"""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
