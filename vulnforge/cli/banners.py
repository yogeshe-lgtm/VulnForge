"""Terminal banners, headers, and visual components."""

from typing import Any, Dict, List, Optional

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnforge import __version__
from vulnforge.core.context import ScanStatistics
from vulnforge.models.target import Target

BANNER_ART = r"""
__      __    _         ______                   
\ \    / /   | |       |  ____|                  
 \ \  / /   _| |_ __   | |__ ___  _ __ __ _  ___ 
  \ \/ / | | | | '_ \  |  __/ _ \| '__/ _` |/ _ \
   \  /| |_| | | | | | | | | (_) | | | (_| |  __/
    \/  \__,_|_|_| |_| |_|  \___/|_|  \__, |\___|
                                       __/ |     
                                      |___/      
"""


def render_banner(console: Console, compact: bool = False) -> None:
    """Display the official VulnForge ASCII banner and metadata."""
    if compact:
        console.print(
            f"[bold cyan]VulnForge[/bold cyan] [dim]v{__version__}[/dim] - "
            "[bold white]Web Security Assessment Engine[/bold white] "
            "[dim red](Authorized Testing Only)[/dim red]"
        )
        return

    banner_text = Text(BANNER_ART, style="bold cyan")
    subtitle = Text.assemble(
        ("VULNFORGE", "bold white"),
        (" - Web Security Assessment Engine\n", "dim cyan"),
        (f"Version {__version__}  |  ", "grey70"),
        ("Authorized Security Testing Only", "bold red"),
    )

    panel = Panel(
        Group(Align.center(banner_text), Align.center(subtitle)),
        border_style="cyan",
        padding=(0, 1),
    )
    console.print(panel)


def render_target_summary(console: Console, target: Target, profile: str) -> None:
    """Display scan target summary details table."""
    table = Table(title="[bold cyan]TARGET PROFILE[/bold cyan]", border_style="dim")
    table.add_column("Parameter", style="bold white", width=18)
    table.add_column("Value", style="cyan")

    table.add_row("Target URL", target.raw_url)
    table.add_row("Normalized URL", target.normalized_url)
    table.add_row("Hostname", target.hostname)
    table.add_row("Port / Scheme", f"{target.port} ({target.scheme.upper()})")
    table.add_row("Scan Profile", profile.upper())
    table.add_row("Allowed Scope", ", ".join(target.scope) if target.scope else "Default (Target Domain)")
    table.add_row("Private IP Target", "[yellow]YES (Local/Lab)[/yellow]" if target.is_private else "[green]NO (Public)[/green]")

    console.print(table)


def render_statistics(console: Console, stats: ScanStatistics) -> None:
    """Display scan statistics panel."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold white", justify="left")
    table.add_column(style="bold cyan", justify="right")

    table.add_row("Requests Sent", str(stats.requests_sent))
    table.add_row("Successful (2xx)", f"[green]{stats.requests_successful}[/green]")
    table.add_row("HTTP Errors (4xx/5xx)", f"[yellow]{stats.http_errors}[/yellow]" if stats.http_errors else "0")
    table.add_row("Failed / Unreachable", f"[red]{stats.requests_failed}[/red]" if stats.requests_failed else "0")
    table.add_row("Blocked (Out of Scope)", f"[red]{stats.requests_blocked}[/red]" if stats.requests_blocked else "0")
    table.add_row("Timeouts", f"[yellow]{stats.timeouts}[/yellow]" if stats.timeouts else "0")
    table.add_row("Redirects Followed", str(stats.redirects))
    table.add_row("Scan Duration", stats.duration_formatted)

    panel = Panel(
        table,
        title="[bold cyan]SCAN STATISTICS[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def render_attack_surface_dashboard(
    console: Console,
    urls_count: int,
    endpoints_count: int,
    parameters_count: int,
    forms_count: int,
    js_count: int,
    apis_count: int,
    tech_count: int,
) -> None:
    """Display the consolidated Attack Surface Summary dashboard panel."""
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="bold white", justify="left")
    grid.add_column(style="bold cyan", justify="right")

    grid.add_row("URLs Visited", str(urls_count))
    grid.add_row("Endpoints Discovered", str(endpoints_count))
    grid.add_row("Parameters Discovered", str(parameters_count))
    grid.add_row("Forms Discovered", str(forms_count))
    grid.add_row("JavaScript Assets", str(js_count))
    grid.add_row("API Routes", f"[green]{apis_count}[/green]")
    grid.add_row("Technologies Identified", str(tech_count))

    panel = Panel(
        grid,
        title="[bold cyan]ATTACK SURFACE SUMMARY[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def render_attack_surface_summary(console: Console, surface: Any) -> None:
    """Display the Attack Surface Intelligence summary panel."""
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="bold white", justify="left")
    grid.add_column(style="bold cyan", justify="right")

    grid.add_row("Hosts", str(len(surface.hosts)))
    grid.add_row("Endpoints", str(surface.total_endpoints))
    grid.add_row("Parameters", str(surface.total_parameters))
    grid.add_row("Forms", str(len(surface.forms)))
    grid.add_row("API Endpoints", f"[green]{len(surface.api_endpoints)}[/green]")
    grid.add_row("JavaScript Assets", str(len(surface.javascript_assets)))
    grid.add_row("Technologies", str(len(surface.technologies)))
    grid.add_row("High-Priority Inputs", f"[yellow]{surface.high_priority_inputs_count}[/yellow]" if surface.high_priority_inputs_count else "0")

    panel = Panel(
        grid,
        title="[bold cyan]ATTACK SURFACE[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def render_endpoint_priority_table(console: Console, endpoints: List[Any], limit: int = 10) -> None:
    """Display prioritized attack surface endpoints."""
    if not endpoints:
        return
    table = Table(title="[bold cyan]PRIORITIZED ENDPOINTS[/bold cyan]", border_style="dim")
    table.add_column("Score", justify="center", width=7)
    table.add_column("Level", width=10)
    table.add_column("Method", width=7)
    table.add_column("URL / Path", style="bold white")
    table.add_column("Classifications", style="cyan")
    table.add_column("Primary Reason", style="dim")

    for ep in endpoints[:limit]:
        score = getattr(ep, "priority_score", 50)
        level = getattr(ep, "priority_level", "MEDIUM").upper()
        if level == "CRITICAL":
            level_fmt = "[bold red]CRITICAL[/bold red]"
            score_fmt = f"[bold red]{score}[/bold red]"
        elif level == "HIGH":
            level_fmt = "[red]HIGH[/red]"
            score_fmt = f"[red]{score}[/red]"
        elif level == "MEDIUM":
            level_fmt = "[yellow]MEDIUM[/yellow]"
            score_fmt = f"[yellow]{score}[/yellow]"
        else:
            level_fmt = "[dim green]LOW[/dim green]"
            score_fmt = f"[dim green]{score}[/dim green]"

        classes = getattr(ep, "classifications", [])
        classes_str = ", ".join(classes[:2]) if classes else "GENERAL"
        reasons = getattr(ep, "priority_reasons", [])
        first_reason = reasons[1] if len(reasons) > 1 else (reasons[0] if reasons else "-")

        table.add_row(
            score_fmt,
            level_fmt,
            ep.method,
            ep.url[:65] + "..." if len(ep.url) > 65 else ep.url,
            classes_str,
            first_reason[:45] + "..." if len(first_reason) > 45 else first_reason,
        )
    console.print(table)


def render_parameter_classification_table(console: Console, parameters: List[Any], limit: int = 15) -> None:
    """Display discovered parameters and their intelligence classifications."""
    if not parameters:
        return
    table = Table(title="[bold cyan]INPUT PARAMETER CLASSIFICATIONS[/bold cyan]", border_style="dim")
    table.add_column("Parameter", style="bold white")
    table.add_column("Location", style="yellow")
    table.add_column("Classification", style="cyan")
    table.add_column("Confidence", justify="right")
    table.add_column("Associated Endpoint", style="dim")

    for p in parameters[:limit]:
        cls_name = getattr(p, "classification", "UNKNOWN")
        conf = getattr(p, "classification_confidence", 50)
        conf_color = "green" if conf >= 85 else "yellow" if conf >= 70 else "white"

        table.add_row(
            p.name,
            p.location.value if hasattr(p.location, "value") else str(p.location),
            f"[bold]{cls_name}[/bold]",
            f"[{conf_color}]{conf}%[/{conf_color}]",
            p.endpoint_url[:50] + "..." if len(p.endpoint_url) > 50 else p.endpoint_url,
        )
    console.print(table)


def render_technologies_table(console: Console, technologies: List[Any]) -> None:
    """Display detected technologies table."""
    if not technologies:
        return
    table = Table(title="[bold cyan]IDENTIFIED TECHNOLOGIES[/bold cyan]", border_style="dim")
    table.add_column("Technology", style="bold white")
    table.add_column("Category", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Confidence", justify="right")
    table.add_column("Evidence", style="dim")

    for tech in technologies:
        conf_color = "green" if tech.confidence >= 85 else "yellow" if tech.confidence >= 70 else "white"
        table.add_row(
            tech.name,
            tech.category,
            tech.version or "-",
            f"[{conf_color}]{tech.confidence}%[/{conf_color}]",
            tech.evidence[:60] + "..." if len(tech.evidence) > 60 else tech.evidence,
        )
    console.print(table)


def render_forms_table(console: Console, forms: List[Any], limit: int = 10) -> None:
    """Display discovered HTML forms table."""
    if not forms:
        return
    table = Table(title="[bold cyan]DISCOVERED FORMS[/bold cyan]", border_style="dim")
    table.add_column("Method", style="magenta", width=8)
    table.add_column("Action URL", style="bold white")
    table.add_column("Input Fields", style="cyan")

    for form in forms[:limit]:
        field_summary = ", ".join(f"{f.name} ({f.field_type})" for f in form.fields) if form.fields else "None"
        table.add_row(
            form.method,
            form.action,
            field_summary[:65] + "..." if len(field_summary) > 65 else field_summary,
        )
    if len(forms) > limit:
        table.caption = f"[dim]Showing {limit} of {len(forms)} forms[/dim]"
    console.print(table)


def render_endpoints_table(console: Console, endpoints: List[Any], limit: int = 15) -> None:
    """Display discovered endpoints table."""
    if not endpoints:
        return
    table = Table(title="[bold cyan]DISCOVERED ENDPOINTS[/bold cyan]", border_style="dim")
    table.add_column("Method", style="magenta", width=8)
    table.add_column("Endpoint Route", style="bold white")
    table.add_column("Source", style="cyan", width=12)
    table.add_column("Status", width=8)
    table.add_column("Parameters", style="yellow")

    for ep in endpoints[:limit]:
        status_str = str(ep.status_code) if ep.status_code else "-"
        status_color = "green" if ep.status_code and 200 <= ep.status_code < 300 else "dim"
        param_names = ", ".join(p.name for p in ep.parameters) if ep.parameters else "-"

        table.add_row(
            ep.method,
            ep.url,
            ep.source,
            f"[{status_color}]{status_str}[/{status_color}]",
            param_names[:40] + "..." if len(param_names) > 40 else param_names,
        )
    if len(endpoints) > limit:
        table.caption = f"[dim]Showing {limit} of {len(endpoints)} endpoints[/dim]"
    console.print(table)


def render_scanner_registry_table(console: Console, scanners: List[Any]) -> None:
    """Display the registry of loaded scanner modules."""
    table = Table(title="[bold cyan]REGISTERED SCANNER MODULES[/bold cyan]", border_style="dim")
    table.add_column("Scanner", style="bold white", no_wrap=True)
    table.add_column("Category", style="cyan")
    table.add_column("Mode", style="magenta")
    table.add_column("Status", style="green", justify="center")
    table.add_column("Description", style="dim")

    for s in scanners:
        mode_val = s.mode.value if hasattr(s.mode, "value") else str(s.mode)
        status_label = "[green]Active[/green]" if s.enabled else "[dim]Disabled[/dim]"
        table.add_row(
            s.name,
            s.category,
            mode_val,
            status_label,
            s.description,
        )
    console.print(table)


def render_scanner_engine_summary(
    console: Console,
    scanner_names: List[str],
    endpoints_count: int,
    observations_count: int,
    findings_count: int,
) -> None:
    """Display the scanner execution summary dashboard panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", justify="left")
    grid.add_column(style="bold cyan", justify="right")

    grid.add_row("Scanners Executed", ", ".join(scanner_names) if scanner_names else "None")
    grid.add_row("Endpoints Analyzed", str(endpoints_count))
    grid.add_row("Observations Recorded", f"[cyan]{observations_count}[/cyan]")
    grid.add_row("Findings Synthesized", f"[yellow]{findings_count}[/yellow]" if findings_count else "0")

    panel = Panel(
        grid,
        title="[bold cyan]SCANNER ENGINE SUMMARY[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def render_observations_table(console: Console, observations: List[Any], limit: int = 15) -> None:
    """Display discovered telemetry observations table."""
    if not observations:
        return
    table = Table(title="[bold cyan]ANALYSIS OBSERVATIONS[/bold cyan]", border_style="dim")
    table.add_column("Type", style="magenta", width=22)
    table.add_column("Endpoint", style="bold white")
    table.add_column("Param", style="yellow", width=12)
    table.add_column("Description", style="cyan")
    table.add_column("Conf", justify="right", width=6)

    for obs in observations[:limit]:
        obs_type = obs.observation_type.value if hasattr(obs.observation_type, "value") else str(obs.observation_type)
        table.add_row(
            obs_type,
            obs.endpoint_url[:45] + "..." if len(obs.endpoint_url) > 45 else obs.endpoint_url,
            obs.parameter_name or "-",
            obs.description[:55] + "..." if len(obs.description) > 55 else obs.description,
            f"{obs.confidence}%",
        )
    if len(observations) > limit:
        table.caption = f"[dim]Showing {limit} of {len(observations)} observations[/dim]"
    console.print(table)


def render_findings_table(console: Console, findings: List[Any]) -> None:
    """Display assessment findings table."""
    if not findings:
        return
    table = Table(title="[bold cyan]ASSESSMENT FINDINGS[/bold cyan]", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Title", style="bold white")
    table.add_column("Category", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Endpoint", style="dim")

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_color = "red" if sev in ("HIGH", "CRITICAL") else "yellow" if sev == "MEDIUM" else "cyan" if sev == "LOW" else "dim"
        status_val = f.status.value if hasattr(f.status, "value") else str(f.status)

        table.add_row(
            f"[{sev_color}]{sev}[/{sev_color}]",
            f.title,
            f.category,
            status_val,
            f.endpoint_url[:40] + "..." if len(f.endpoint_url) > 40 else f.endpoint_url,
        )
    console.print(table)


def render_scan_completion_dashboard(
    console: Console,
    target_host: str,
    duration_str: str,
    requests_count: int,
    endpoints_count: int,
    parameters_count: int,
    findings: List[Any],
    reports: Optional[List[str]] = None,
) -> None:
    """Display the final consolidated scan completion dashboard."""
    # Summary grid
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", justify="left", width=14)
    grid.add_column(style="bold cyan", justify="right")

    grid.add_row("Target", target_host)
    grid.add_row("Duration", duration_str)
    grid.add_row("Requests", f"{requests_count:,}")
    grid.add_row("Endpoints", f"{endpoints_count:,}")
    grid.add_row("Parameters", f"{parameters_count:,}")

    panel = Panel(
        grid,
        title="[bold cyan]VULNFORGE SCAN COMPLETE[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)

    # Count breakdown
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    console.print("[bold white]Findings:[/bold white]")
    console.print(f"  [bold red]CRITICAL[/bold red]  {sev_counts['CRITICAL']}")
    console.print(f"  [red]HIGH[/red]      {sev_counts['HIGH']}")
    console.print(f"  [yellow]MEDIUM[/yellow]    {sev_counts['MEDIUM']}")
    console.print(f"  [green]LOW[/green]       {sev_counts['LOW']}")
    console.print(f"  [cyan]INFO[/cyan]      {sev_counts['INFO']}")

    if reports:
        console.print("\n[bold white]Reports:[/bold white]")
        for rep in reports:
            console.print(f"  [green][+][/green] [bold]{rep}[/bold]")
    console.print()


def render_top_findings(console: Console, findings: List[Any], limit: int = 5) -> None:
    """Display top priority findings in high-visibility summary cards."""
    if not findings:
        return

    sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            sev_order.get((f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper(), 0),
            f.confidence,
        ),
        reverse=True,
    )

    console.print("[bold cyan]TOP FINDINGS[/bold cyan]")
    for f in sorted_findings[:limit]:
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
        sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "green" if sev == "LOW" else "cyan"

        endpoint_display = f.endpoint_url
        if f.parameter_name and "?" in endpoint_display:
            endpoint_display = endpoint_display.split("?")[0] + f"?{f.parameter_name}="
        elif f.parameter_name:
            endpoint_display = f"{endpoint_display}?{f.parameter_name}="

        console.print(f"[{sev_color}][{sev}][/{sev_color}] [bold white]{f.title}[/bold white]")
        console.print(f"  [dim cyan]{endpoint_display}[/dim cyan]")
        console.print(f"  [dim]Confidence:[/dim] [bold white]{f.confidence}%[/bold white]\n")


def render_finding_detail(console: Console, finding: Any) -> None:
    """Display complete structured details of an individual security finding."""
    sev = (finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)).upper()
    sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "green" if sev == "LOW" else "cyan"
    status_str = finding.status.value if hasattr(finding.status, "value") else str(finding.status)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=16)
    grid.add_column(style="cyan")

    grid.add_row("Title", str(finding.title))
    grid.add_row("Severity", f"[{sev_color}]{sev}[/{sev_color}]")
    grid.add_row("Confidence", f"{finding.confidence}% ({status_str})")
    grid.add_row("Category", str(finding.category))
    grid.add_row("Endpoint", str(finding.endpoint_url))
    grid.add_row("Parameter", str(finding.parameter_name or "None"))
    grid.add_row("Scanner", str(finding.scanner))

    panel = Panel(
        grid,
        title=f"[{sev_color}][{sev}][/ {sev_color}] {finding.title}",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)

    console.print("[bold cyan]Description:[/bold cyan]")
    console.print(f"  {finding.description}\n")

    if finding.evidence:
        console.print("[bold cyan]Evidence:[/bold cyan]")
        console.print(f"  [dim]{finding.evidence}[/dim]\n")

    curl_cmd = f"curl -i -s -k '{finding.endpoint_url}'"
    console.print("[bold cyan]Reproduction:[/bold cyan]")
    console.print(f"  [green]{curl_cmd}[/green]\n")

    console.print("[bold cyan]Remediation:[/bold cyan]")
    console.print(f"  [yellow]{finding.recommendation}[/yellow]\n")

    if finding.references:
        console.print("[bold cyan]References:[/bold cyan]")
        for r in finding.references:
            console.print(f"  [dim]- {r}[/dim]")
        console.print()


def render_scan_diff_table(console: Console, diff_data: Dict[str, List[Any]]) -> None:
    """Display comparison between two scan sessions."""
    table = Table(title="[bold cyan]SCAN VULNERABILITY COMPARISON (DIFF)[/bold cyan]", border_style="dim")
    table.add_column("Status", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Title", style="bold white")
    table.add_column("Endpoint", style="dim")

    for f in diff_data.get("new", []):
        sev = (f.get("severity") or "INFO").upper()
        table.add_row("[bold green]NEW[/bold green]", f"[bold red]{sev}[/bold red]", f.get("title", ""), f.get("endpoint_url", "")[:45])

    for f in diff_data.get("resolved", []):
        sev = (f.get("severity") or "INFO").upper()
        table.add_row("[bold cyan]RESOLVED[/bold cyan]", f"[dim]{sev}[/dim]", f.get("title", ""), f.get("endpoint_url", "")[:45])

    for f in diff_data.get("unchanged", []):
        sev = (f.get("severity") or "INFO").upper()
        table.add_row("[dim]UNCHANGED[/dim]", sev, f.get("title", ""), f.get("endpoint_url", "")[:45])

    console.print(table)


def render_attack_surface_graph(console: Console, graph: Any) -> None:
    """Display the Attack Surface Graph topology and summary."""
    summary = graph.summary()
    node_counts = summary.get("node_counts", {})

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan", justify="right")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan", justify="right")

    grid.add_row("Total Graph Nodes", str(summary.get("total_nodes", 0)), "Total Graph Edges", str(summary.get("total_edges", 0)))
    grid.add_row("Hosts / Subdomains", str(node_counts.get("HOST", 0)), "API Routes", str(summary.get("api_routes", 0)))
    grid.add_row("Endpoints Mapped", str(node_counts.get("ENDPOINT", 0)), "High-Value Targets", str(summary.get("high_value_endpoints", 0)))
    grid.add_row("Parameters Mapped", str(node_counts.get("PARAMETER", 0)), "Auth Boundaries", str(node_counts.get("AUTH_BOUNDARY", 0)))
    grid.add_row("JavaScript Assets", str(node_counts.get("JAVASCRIPT", 0)), "Findings Attached", str(node_counts.get("FINDING", 0)))

    panel = Panel(
        grid,
        title="[bold cyan]ATTACK SURFACE GRAPH TOPOLOGY[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    tree_str = graph.render_ascii_tree()
    console.print("[bold cyan]GRAPH HIERARCHY TREE[/bold cyan]")
    console.print(Panel(tree_str, border_style="dim", padding=(1, 2)))
    console.print()


def render_regression_report(console: Console, report: Any) -> None:
    """Display complete structured security regression analysis between two scans."""
    summary = report.summary()

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan", justify="right")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan", justify="right")

    grid.add_row("Baseline Scan ID", str(report.baseline_scan_id)[:14], "Candidate Scan ID", str(report.current_scan_id)[:14])
    grid.add_row("New Findings", f"[green]{summary['new']}[/green]", "Resolved Findings", f"[cyan]{summary['resolved']}[/cyan]")
    grid.add_row("Regressed / Reopened", f"[bold red]{summary['regressed']}[/bold red]" if summary['regressed'] > 0 else "[dim]0[/dim]", "Unchanged Findings", str(summary['unchanged']))
    grid.add_row("New Endpoints Discovered", str(summary['new_endpoints_count']), "Blocking Regressions", "[bold red]YES[/bold red]" if summary['blocking'] else "[green]NO[/green]")

    panel = Panel(
        grid,
        title="[bold cyan]SECURITY REGRESSION & DELTA ANALYSIS[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    table = Table(title="[bold cyan]ITEMIZED FINDING DELTAS[/bold cyan]", border_style="dim")
    table.add_column("Status", width=14)
    table.add_column("Severity", width=10)
    table.add_column("Title", style="bold white")
    table.add_column("Endpoint", style="dim")
    table.add_column("Comparative Analysis", style="yellow")

    for item in report.finding_regressions:
        status_str = item.status.value
        if status_str in ("REGRESSED", "REOPENED"):
            status_colored = f"[bold red]{status_str}[/bold red]"
        elif status_str == "NEW":
            status_colored = f"[bold green]{status_str}[/bold green]"
        elif status_str == "RESOLVED":
            status_colored = f"[bold cyan]{status_str}[/bold cyan]"
        else:
            status_colored = f"[dim]{status_str}[/dim]"

        sev_colored = f"[bold red]{item.severity}[/bold red]" if item.severity in ("CRITICAL", "HIGH") else item.severity
        table.add_row(
            status_colored,
            sev_colored,
            item.title[:35],
            item.endpoint_url[:40],
            item.explanation,
        )

    console.print(table)
    console.print()


def render_api_analysis_table(console: Console, analysis: Any) -> None:
    """Display API discovery and security analysis summary."""
    spec = analysis.spec
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")

    grid.add_row("API Architecture", analysis.api_type.value, "Spec Title", spec.title if spec else "None")
    grid.add_row("Documented Routes", str(analysis.documented_endpoints_count), "Discovered Routes", str(analysis.discovered_endpoints_count))
    grid.add_row("Undocumented Endpoints", f"[bold red]{len(analysis.undocumented_endpoints)}[/bold red]" if analysis.undocumented_endpoints else "[green]0[/green]", "Dangerous Methods", f"[yellow]{len(analysis.potentially_dangerous_methods)}[/yellow]" if analysis.potentially_dangerous_methods else "[green]0[/green]")

    panel = Panel(
        grid,
        title="[bold cyan]API ATTACK SURFACE & SECURITY ASSESSMENT[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    if analysis.undocumented_endpoints:
        table_undoc = Table(title="[bold red]SHADOW / UNDOCUMENTED API ENDPOINTS[/bold red]", border_style="red")
        table_undoc.add_column("Discovered Route", style="bold white")
        table_undoc.add_column("Status", style="bold red")
        for ep_str in analysis.undocumented_endpoints[:15]:
            table_undoc.add_row(ep_str, "MISSING FROM SPEC")
        console.print(table_undoc)
        console.print()

    if analysis.potentially_dangerous_methods:
        table_dang = Table(title="[bold yellow]POTENTIALLY DANGEROUS / UNAUTHENTICATED METHODS[/bold yellow]", border_style="yellow")
        table_dang.add_column("Route & Method", style="bold white")
        for m in analysis.potentially_dangerous_methods[:15]:
            table_dang.add_row(m)
        console.print(table_dang)
        console.print()


def render_graphql_analysis_table(console: Console, analysis: Any) -> None:
    """Display GraphQL security and introspection analysis results."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")

    grid.add_row("GraphQL Endpoint", analysis.endpoint_url, "Introspection", "[bold red]ENABLED[/bold red]" if analysis.introspection_enabled else "[green]DISABLED[/green]")
    grid.add_row("Root Query Type", analysis.query_type_name or "None", "Exposed Queries", str(analysis.queries_count))
    grid.add_row("Root Mutation Type", analysis.mutation_type_name or "None", "Exposed Mutations", str(analysis.mutations_count))
    grid.add_row("Field Suggestions", "[yellow]ENABLED[/yellow]" if analysis.suggestions_enabled else "[green]DISABLED[/green]", "Sensitive Fields", f"[bold red]{len(analysis.sensitive_fields)}[/bold red]" if analysis.sensitive_fields else "[green]0[/green]")

    panel = Panel(
        grid,
        title="[bold cyan]GRAPHQL SECURITY & INTROSPECTION AUDIT[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    if analysis.sensitive_fields:
        table_sens = Table(title="[bold red]POTENTIALLY SENSITIVE SCHEMA FIELDS[/bold red]", border_style="red")
        table_sens.add_column("Type & Field", style="bold white")
        for f in analysis.sensitive_fields[:20]:
            table_sens.add_row(f)
        console.print(table_sens)
        console.print()


def render_jwt_analysis_table(console: Console, analysis: Any) -> None:
    """Display JWT token decoding and security vulnerability analysis."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")

    alg_colored = f"[bold red]{analysis.algorithm}[/bold red]" if analysis.is_none_algorithm else f"[green]{analysis.algorithm}[/green]"
    exp_status = "[bold red]EXPIRED[/bold red]" if analysis.is_expired else "[green]VALID[/green]" if analysis.is_expired is False else "[yellow]NONE (NEVER EXPIRES)[/yellow]"

    grid.add_row("Algorithm (alg)", alg_colored, "Token Structure", "[green]VALID RFC 7519[/green]" if analysis.is_valid_structure else "[red]MALFORMED[/red]")
    grid.add_row("Key ID (kid)", analysis.key_id or "None", "Expiration Status", exp_status)
    grid.add_row("Issued At (iat)", analysis.issued_at or "-", "Expires At (exp)", analysis.expires_at or "-")
    grid.add_row("Sensitive Claims Exposed", f"[bold red]{len(analysis.sensitive_claims_exposed)}[/bold red]" if analysis.sensitive_claims_exposed else "[green]0[/green]", "Identified Weaknesses", f"[yellow]{len(analysis.weaknesses)}[/yellow]" if analysis.weaknesses else "[green]0[/green]")

    panel = Panel(
        grid,
        title="[bold cyan]JSON WEB TOKEN (JWT) SECURITY ANALYSIS[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    if analysis.header:
        console.print("[bold cyan]JOSE Header:[/bold cyan]")
        console.print(Panel(str(analysis.header), border_style="dim"))
        console.print()

    if analysis.claims:
        console.print("[bold cyan]Decoded Claims Payload (Secrets Redacted):[/bold cyan]")
        console.print(Panel(str(analysis.claims), border_style="dim"))
        console.print()

    if analysis.weaknesses:
        table_weak = Table(title="[bold yellow]IDENTIFIED TOKEN WEAKNESSES[/bold yellow]", border_style="yellow")
        table_weak.add_column("Weakness / Anomaly", style="bold white")
        for w in analysis.weaknesses:
            table_weak.add_row(w)
        console.print(table_weak)
        console.print()


def render_websocket_analysis_table(console: Console, analysis: Any) -> None:
    """Display WebSocket handshake and CSWSH security audit results."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")

    upgrade_str = "[bold green]101 SWITCHING PROTOCOLS[/bold green]" if analysis.is_upgrade_supported else f"[dim]HTTP {analysis.status_code}[/dim]"
    cswsh_str = "[bold red]ARBITRARY ORIGIN ACCEPTED (CSWSH RISK)[/bold red]" if analysis.allows_arbitrary_origin else "[green]ORIGIN VALIDATED / REJECTED[/green]"
    transport_str = "[bold red]UNENCRYPTED (ws:// or http://)[/bold red]" if analysis.is_unencrypted else "[green]TLS ENCRYPTED (wss://)[/green]"

    grid.add_row("Endpoint URL", analysis.endpoint_url, "Upgrade Handshake", upgrade_str)
    grid.add_row("Transport Security", transport_str, "Origin Validation", cswsh_str)
    grid.add_row("Requires Auth", "[cyan]YES[/cyan]" if analysis.requires_authentication else "[dim]NO[/dim]", "Subprotocols", ", ".join(analysis.subprotocols_supported) if analysis.subprotocols_supported else "None")

    panel = Panel(
        grid,
        title="[bold cyan]WEBSOCKET PROTOCOL & CSWSH AUDIT[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


def render_fuzz_results_table(console: Console, summary: Any) -> None:
    """Display controlled fuzzing campaign summary and discovered routes."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")

    dist_str = ", ".join(f"{st}: {ct}" for st, ct in summary.status_distribution.items())
    grid.add_row("Target Base URL", summary.target_base_url, "Total Probes Sent", str(summary.total_requests_sent))
    grid.add_row("Discovered Routes", f"[bold green]{summary.discovered_endpoints_count}[/bold green]", "Status Distribution", dist_str or "None")

    panel = Panel(
        grid,
        title="[bold cyan]CONTROLLED FUZZING CAMPAIGN SUMMARY[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()

    if summary.results:
        table = Table(title="[bold cyan]DISCOVERED ENDPOINTS & ANOMALIES[/bold cyan]", border_style="dim")
        table.add_column("Status", width=8)
        table.add_column("Payload / Route", style="bold white")
        table.add_column("Size", justify="right", width=10)
        table.add_column("Latency", justify="right", width=10)
        table.add_column("Observation Note", style="yellow")

        for r in summary.results[:25]:
            status_color = "green" if r.status_code == 200 else "cyan" if 300 <= r.status_code < 400 else "yellow" if r.status_code in (401, 403) else "red"
            table.add_row(
                f"[{status_color}]{r.status_code}[/{status_color}]",
                r.payload,
                f"{r.response_size} B",
                f"{r.elapsed_ms:.1f} ms",
                r.note,
            )
        console.print(table)
        console.print()


def render_ci_policy_summary(
    console: Console,
    target: str,
    total_findings: int,
    blocking_findings: int,
    is_passed: bool,
    threshold: str,
    regressions_count: int = 0,
) -> None:
    """Display CI/CD security gate policy pass/fail outcome banner."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")
    grid.add_column(style="bold white", width=22)
    grid.add_column(style="cyan")

    status_str = "[bold green]PASSED (NO BLOCKING VULNERABILITIES)[/bold green]" if is_passed else "[bold red]FAILED (POLICY THRESHOLD EXCEEDED)[/bold red]"
    border_color = "green" if is_passed else "red"

    grid.add_row("Target", target, "Policy Outcome", status_str)
    grid.add_row("Fail-On Threshold", f"[yellow]{threshold.upper()}[/yellow]", "Total Findings", str(total_findings))
    grid.add_row("Blocking Findings", f"[bold red]{blocking_findings}[/bold red]" if blocking_findings > 0 else "[green]0[/green]", "Regressions", f"[bold red]{regressions_count}[/bold red]" if regressions_count > 0 else "[green]0[/green]")

    panel = Panel(
        grid,
        title=f"[bold {border_color}]VULNFORGE CI/CD SECURITY GATE[/bold {border_color}]",
        border_style=border_color,
        padding=(1, 2),
    )
    console.print(panel)
    console.print()






