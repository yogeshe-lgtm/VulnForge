"""Typer CLI entry point for VulnForge."""

import asyncio
from typing import List, Optional
import typer

from vulnforge.cli.commands import (
    cmd_config_init,
    cmd_config_show,
    cmd_diff,
    cmd_history,
    cmd_scanners,
    cmd_show,
    cmd_version,
    execute_crawl,
    execute_recon,
    execute_scan,
    execute_surface,
)
from vulnforge.core.config import get_default_config_path

app = typer.Typer(
    name="vulnforge",
    help="VulnForge - Professional Web Security Assessment Engine (Authorized Testing Only)",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

config_app = typer.Typer(
    name="config",
    help="Manage VulnForge settings and configuration file.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


@app.command("version")
def version() -> None:
    """Show VulnForge version and licensing information."""
    cmd_version()


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="Target URL to assess (e.g. https://example.com)"),
    scope: Optional[List[str]] = typer.Option(
        None, "--scope", "-s", help="Authorized domain scope pattern (e.g. *.example.com). Can be specified multiple times."
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", "-e", help="Domain to explicitly exclude from testing. Can be specified multiple times."
    ),
    exclude_path: Optional[List[str]] = typer.Option(
        None, "--exclude-path", help="Path prefix to exclude (e.g. /logout, /admin/delete). Can be specified multiple times."
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", min=1, max=50, help="Maximum concurrent worker threads/tasks."
    ),
    rate: Optional[float] = typer.Option(
        None, "--rate", "-r", min=0.1, help="Maximum requests per second."
    ),
    timeout: Optional[float] = typer.Option(
        None, "--timeout", min=1.0, max=120.0, help="HTTP request timeout in seconds."
    ),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H", help="Custom HTTP request header (e.g. 'Authorization: Bearer token')."
    ),
    cookie: Optional[List[str]] = typer.Option(
        None, "--cookie", "-c", help="Custom HTTP cookie (e.g. 'session=xyz')."
    ),
    user_agent: Optional[str] = typer.Option(
        None, "--user-agent", "-u", help="Custom HTTP User-Agent string."
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", "-p", help="Proxy URL (e.g. http://127.0.0.1:8080)."
    ),
    only: Optional[List[str]] = typer.Option(
        None, "--only", help="Scanner module or category to run exclusively (e.g. 'xss,sqli'). Can be specified multiple times."
    ),
    scanner: Optional[List[str]] = typer.Option(
        None, "--scanner", help="Scanner module to execute (alias for --only)."
    ),
    exclude_scanner: Optional[List[str]] = typer.Option(
        None, "--exclude-scanner", "--exclude-scanners", help="Scanner module or category to exclude from execution."
    ),
    profile: str = typer.Option(
        "safe", "--profile", help="Scan profile: 'passive', 'safe', 'balanced', or 'custom'."
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="File path to export scan report."
    ),
    format_opt: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: 'terminal', 'json', 'html', or 'markdown'."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose execution output."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress banner and non-essential output."
    ),
    allow_private: bool = typer.Option(
        True, "--allow-private", help="Allow private/loopback/lab IP addresses."
    ),
) -> None:
    """Initiate a structured web security assessment session on the target."""
    merged_includes = []
    if only:
        merged_includes.extend(only)
    if scanner:
        merged_includes.extend(scanner)

    exit_code = asyncio.run(
        execute_scan(
            target_url=target,
            scope_list=scope,
            exclude_list=exclude,
            exclude_paths=exclude_path,
            include_scanners=merged_includes if merged_includes else None,
            exclude_scanners=exclude_scanner,
            threads=threads,
            rate=rate,
            timeout=timeout,
            headers=header,
            cookies=cookie,
            user_agent=user_agent,
            proxy=proxy,
            profile=profile,
            verbose=verbose,
            quiet=quiet,
            allow_private=allow_private,
            output=output,
            output_format=format_opt,
        )
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command("show")
def show(
    scan_id: Optional[str] = typer.Argument(
        None, help="Scan ID to inspect (defaults to latest scan session)."
    )
) -> None:
    """Display comprehensive details, findings, evidence, and remediation for a scan session."""
    cmd_show(scan_id)


@app.command("diff")
def diff(
    scan_1: str = typer.Argument(..., help="Baseline scan ID (older scan)."),
    scan_2: str = typer.Argument(..., help="Target comparison scan ID (newer scan)."),
) -> None:
    """Compare security findings between two scan sessions to identify new and resolved issues."""
    cmd_diff(scan_1, scan_2)


@app.command("crawl")

def crawl(
    target: str = typer.Argument(..., help="Target seed URL to crawl (e.g. https://example.com)"),
    depth: int = typer.Option(
        3, "--depth", "-d", min=1, max=10, help="Maximum crawl depth."
    ),
    scope: Optional[List[str]] = typer.Option(
        None, "--scope", "-s", help="Authorized domain scope pattern (e.g. *.example.com). Can be specified multiple times."
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", "-e", help="Domain to explicitly exclude from crawling."
    ),
    exclude_path: Optional[List[str]] = typer.Option(
        None, "--exclude-path", help="Path prefix to exclude (e.g. /logout)."
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", min=1, max=50, help="Maximum concurrent crawl workers."
    ),
    rate: Optional[float] = typer.Option(
        None, "--rate", "-r", min=0.1, help="Maximum requests per second."
    ),
    timeout: Optional[float] = typer.Option(
        None, "--timeout", min=1.0, max=120.0, help="HTTP request timeout in seconds."
    ),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H", help="Custom HTTP request header."
    ),
    cookie: Optional[List[str]] = typer.Option(
        None, "--cookie", "-c", help="Custom HTTP cookie."
    ),
    user_agent: Optional[str] = typer.Option(
        None, "--user-agent", "-u", help="Custom HTTP User-Agent string."
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", "-p", help="Proxy URL (e.g. http://127.0.0.1:8080)."
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="File path to export discovered attack surface (JSON)."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress banner."
    ),
    allow_private: bool = typer.Option(
        True, "--allow-private", help="Allow private/loopback IP addresses."
    ),
) -> None:
    """Asynchronously crawl target, map endpoint tree, extract forms, and parse JavaScript assets."""
    exit_code = asyncio.run(
        execute_crawl(
            target_url=target,
            depth=depth,
            scope_list=scope,
            exclude_list=exclude,
            exclude_paths=exclude_path,
            threads=threads,
            rate=rate,
            timeout=timeout,
            headers=header,
            cookies=cookie,
            user_agent=user_agent,
            proxy=proxy,
            verbose=verbose,
            quiet=quiet,
            allow_private=allow_private,
            output=output,
        )
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command("recon")
def recon(
    target: str = typer.Argument(..., help="Target URL for reconnaissance (e.g. https://example.com)"),
    scope: Optional[List[str]] = typer.Option(
        None, "--scope", "-s", help="Authorized domain scope pattern."
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", "-e", help="Domain to explicitly exclude from reconnaissance."
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", min=1, max=50, help="Maximum concurrent workers."
    ),
    rate: Optional[float] = typer.Option(
        None, "--rate", "-r", min=0.1, help="Maximum requests per second."
    ),
    timeout: Optional[float] = typer.Option(
        None, "--timeout", min=1.0, max=120.0, help="HTTP request timeout in seconds."
    ),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H", help="Custom HTTP request header."
    ),
    cookie: Optional[List[str]] = typer.Option(
        None, "--cookie", "-c", help="Custom HTTP cookie."
    ),
    user_agent: Optional[str] = typer.Option(
        None, "--user-agent", "-u", help="Custom HTTP User-Agent string."
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", "-p", help="Proxy URL (e.g. http://127.0.0.1:8080)."
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="File path to export reconnaissance results (JSON)."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress banner."
    ),
    allow_private: bool = typer.Option(
        True, "--allow-private", help="Allow private/loopback IP addresses."
    ),
) -> None:
    """Run target reconnaissance: inspect robots.txt, sitemaps, headers, and fingerprint technologies."""
    exit_code = asyncio.run(
        execute_recon(
            target_url=target,
            scope_list=scope,
            exclude_list=exclude,
            threads=threads,
            rate=rate,
            timeout=timeout,
            headers=header,
            cookies=cookie,
            user_agent=user_agent,
            proxy=proxy,
            verbose=verbose,
            quiet=quiet,
            allow_private=allow_private,
            output=output,
        )
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command("surface")
def surface(
    target: str = typer.Argument(..., help="Target seed URL to map attack surface (e.g. https://example.com)"),
    depth: int = typer.Option(
        3, "--depth", "-d", min=1, max=10, help="Maximum crawl depth for attack surface mapping."
    ),
    scope: Optional[List[str]] = typer.Option(
        None, "--scope", "-s", help="Authorized domain scope pattern (e.g. *.example.com). Can be specified multiple times."
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", "-e", help="Domain to explicitly exclude from attack surface discovery."
    ),
    exclude_path: Optional[List[str]] = typer.Option(
        None, "--exclude-path", help="Path prefix to exclude (e.g. /logout)."
    ),
    threads: Optional[int] = typer.Option(
        None, "--threads", "-t", min=1, max=50, help="Maximum concurrent worker tasks."
    ),
    rate: Optional[float] = typer.Option(
        None, "--rate", "-r", min=0.1, help="Maximum requests per second."
    ),
    timeout: Optional[float] = typer.Option(
        None, "--timeout", min=1.0, max=120.0, help="HTTP request timeout in seconds."
    ),
    header: Optional[List[str]] = typer.Option(
        None, "--header", "-H", help="Custom HTTP request header."
    ),
    cookie: Optional[List[str]] = typer.Option(
        None, "--cookie", "-c", help="Custom HTTP cookie."
    ),
    user_agent: Optional[str] = typer.Option(
        None, "--user-agent", "-u", help="Custom HTTP User-Agent string."
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", "-p", help="Proxy URL (e.g. http://127.0.0.1:8080)."
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="File path to export Attack Surface model (JSON)."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose output."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress banner."
    ),
    allow_private: bool = typer.Option(
        True, "--allow-private", help="Allow private/loopback IP addresses."
    ),
) -> None:
    """Analyze, classify, prioritize, and summarize the attack surface of the target."""
    exit_code = asyncio.run(
        execute_surface(
            target_url=target,
            depth=depth,
            scope_list=scope,
            exclude_list=exclude,
            exclude_paths=exclude_path,
            threads=threads,
            rate=rate,
            timeout=timeout,
            headers=header,
            cookies=cookie,
            user_agent=user_agent,
            proxy=proxy,
            verbose=verbose,
            quiet=quiet,
            allow_private=allow_private,
            output=output,
        )
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command("scanners")
def scanners() -> None:
    """List available security vulnerability scanners and modules."""
    cmd_scanners()


@app.command("history")
def history(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of historical scans to display.")
) -> None:
    """View past scan sessions recorded in local SQLite database."""
    cmd_history(limit=limit)


@config_app.command("show")
def config_show() -> None:
    """Display active configuration settings."""
    cmd_config_show()


@config_app.command("init")
def config_init() -> None:
    """Initialize default configuration file."""
    cmd_config_init()


@config_app.command("path")
def config_path() -> None:
    """Print configuration file path."""
    typer.echo(str(get_default_config_path()))


if __name__ == "__main__":
    app()
