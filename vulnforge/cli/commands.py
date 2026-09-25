"""CLI Command implementations for VulnForge with end-to-end scanning workflow."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vulnforge import __version__
from vulnforge.cli.banners import (
    render_api_analysis_table,
    render_attack_surface_dashboard,
    render_attack_surface_graph,
    render_attack_surface_summary,
    render_banner,
    render_ci_policy_summary,
    render_endpoint_priority_table,
    render_endpoints_table,
    render_finding_detail,
    render_findings_table,
    render_forms_table,
    render_fuzz_results_table,
    render_graphql_analysis_table,
    render_jwt_analysis_table,
    render_observations_table,
    render_parameter_classification_table,
    render_regression_report,
    render_scan_completion_dashboard,
    render_scan_diff_table,
    render_scanner_engine_summary,
    render_scanner_registry_table,
    render_statistics,
    render_target_summary,
    render_technologies_table,
    render_top_findings,
    render_websocket_analysis_table,
)
from vulnforge.api import GraphQLAnalyzer, OpenAPIParser, OpenAPIScanner
from vulnforge.protocols import JWTAnalyzer, WebSocketAnalyzer
from vulnforge.intelligence import AttackSurfaceBuilder, AttackSurfaceGraph
from vulnforge.fuzz import ControlledFuzzer, FuzzSummary
from vulnforge.reporting.sarif import SARIFReportGenerator
from vulnforge.integrations import ProxyAdapter


from vulnforge.cli.themes import SECURITY_THEME
from vulnforge.core.config import (
    VulnForgeConfig,
    ensure_config_dir,
    get_default_config_path,
    load_config,
    save_config,
)
from vulnforge.core.context import ScanContext
from vulnforge.core.engine import HttpEngine
from vulnforge.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    ScopeViolationError,
    TargetValidationError,
    VulnForgeException,
)
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.correlation.engine import CorrelationEngine
from vulnforge.correlation.regression import SecurityRegressionEngine
from vulnforge.crawler.crawler import WebCrawler
from vulnforge.crawler.sitemap import parse_robots_txt, parse_sitemap_xml
from vulnforge.discovery.endpoints import EndpointInventory
from vulnforge.discovery.javascript import extract_endpoints_from_js
from vulnforge.discovery.parameters import ParameterInventory
from vulnforge.discovery.technologies import TechnologyFingerprinter
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.models.target import Target
from vulnforge.reporting import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
)
from vulnforge.scanners import (
    Finding,
    Observation,
    ScannerEngine,
    ScannerRegistry,
)
from vulnforge.storage.database import DatabaseManager

console = Console(theme=SECURITY_THEME)


def parse_key_value_pairs(items: Optional[List[str]]) -> Dict[str, str]:
    """Parse list of 'Key: Value' or 'Key=Value' strings into a dictionary."""
    result = {}
    if not items:
        return result
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            result[k.strip()] = v.strip()
        elif "=" in item:
            k, v = item.split("=", 1)
            result[k.strip()] = v.strip()
    return result


async def execute_scan(
    target_url: str,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
    include_scanners: Optional[List[str]] = None,
    exclude_scanners: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
    output_format: str = "terminal",
) -> int:
    """Execute complete end-to-end security assessment scan."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent
    scan_profile = profile or cfg.default_profile
    crawl_depth = cfg.crawl_depth

    # Resolve active scanner filters
    final_includes = include_scanners or cfg.enabled_scanners
    final_excludes = exclude_scanners or cfg.excluded_scanners

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=scan_profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(
        allowed_domains=target.scope,
        excluded_domains=exclude_list,
        excluded_paths=exclude_paths,
    )

    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)

    context = ScanContext(
        target=target,
        config=cfg,
        scope=scope_engine,
        rate_limiter=rate_limiter,
    )

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="running")

    if not quiet:
        render_target_summary(console, target, scan_profile)
        console.print(
            f"[dim cyan]Concurrency:[/dim cyan] [bold white]{scan_threads}[/bold white]  "
            f"[dim cyan]Rate Limit:[/dim cyan] [bold white]{scan_rate} req/s[/bold white]  "
            f"[dim cyan]Timeout:[/dim cyan] [bold white]{scan_timeout}s[/bold white]  "
            f"[dim cyan]Crawl Depth:[/dim cyan] [bold white]{crawl_depth}[/bold white]"
        )
        console.print(f"[dim]Scan ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    exit_code = 0
    status_label = "completed"
    endpoint_inventory = EndpointInventory()
    param_inventory = ParameterInventory()
    fingerprinter = TechnologyFingerprinter()
    observations: List[Observation] = []
    findings: List[Finding] = []
    generated_reports: List[str] = []

    try:
        # STEP 1: Baseline Probe & Recon
        with console.status("[bold cyan]Probing target baseline...[/bold cyan]", spinner="dots"):
            root_resp = await http_engine.get(
                target.normalized_url,
                headers=parsed_headers,
                cookies=parsed_cookies,
            )

        db.log_http_request(
            scan_id=context.scan_id,
            method=root_resp.request_method,
            url=root_resp.url,
            status_code=root_resp.status_code,
            elapsed_ms=root_resp.elapsed * 1000,
        )

        root_ep = Endpoint.from_url(
            target.normalized_url,
            method="GET",
            source="probe",
            status_code=root_resp.status_code,
            content_type=root_resp.content_type,
        )
        endpoint_inventory.add(root_ep)
        for p in root_ep.parameters:
            param_inventory.add(p)

        fingerprinter.analyze_response(root_resp)

        # STEP 2: Reconnaissance (robots.txt and sitemap.xml)
        if not context.is_cancelled:
            with console.status("[bold cyan]Inspecting robots.txt and sitemaps...[/bold cyan]", spinner="dots"):
                parsed_root = urlparse(target.normalized_url)
                base_root = f"{parsed_root.scheme}://{parsed_root.netloc}"
                robots_url = f"{base_root}/robots.txt"

                if context.scope.is_allowed(robots_url):
                    try:
                        rob_resp = await http_engine.get(robots_url)
                        if rob_resp.is_success and "text" in rob_resp.content_type.lower():
                            rob_res = parse_robots_txt(rob_resp.body, base_root)
                            for r_url in rob_res.discovered_urls:
                                if context.scope.is_allowed(r_url):
                                    ep = Endpoint.from_url(r_url, method="GET", source="robots.txt")
                                    endpoint_inventory.add(ep)
                                    for p in ep.parameters:
                                        param_inventory.add(p)
                            for sm in rob_res.sitemaps:
                                if context.scope.is_allowed(sm):
                                    try:
                                        sm_resp = await http_engine.get(sm)
                                        if sm_resp.is_success:
                                            for sm_url in parse_sitemap_xml(sm_resp.body, base_root):
                                                if context.scope.is_allowed(sm_url):
                                                    ep = Endpoint.from_url(sm_url, method="GET", source="sitemap.xml")
                                                    endpoint_inventory.add(ep)
                                    except Exception:
                                        pass
                    except Exception:
                        pass

        # STEP 3: Web Crawling & Endpoint Discovery
        if crawl_depth > 0 and not context.is_cancelled:
            with console.status(f"[bold cyan]Crawling endpoints (depth: {crawl_depth})...[/bold cyan]", spinner="dots") as status_bar:
                crawler = WebCrawler(context=context, max_depth=crawl_depth)

                def on_progress(url: str, d: int, total: int) -> None:
                    status_bar.update(f"[bold cyan]Crawling [depth {d} | visited {total}]:[/bold cyan] [dim]{url[:60]}[/dim]")

                crawler.progress_callback = on_progress
                crawl_result = await crawler.crawl(target.normalized_url)

                for ep in crawl_result.endpoints:
                    endpoint_inventory.add(ep)
                for p in crawl_result.parameters:
                    param_inventory.add(p)

                # Analyze JavaScript Assets
                for js_url in list(crawl_result.scripts)[:10]:
                    if context.scope.is_allowed(js_url):
                        try:
                            js_resp = await http_engine.get(js_url)
                            if js_resp.is_success and js_resp.body:
                                js_disc = extract_endpoints_from_js(js_resp.body, js_url, target.base_url())
                                for js_ep in js_disc.discovered_endpoints:
                                    if context.scope.is_allowed(js_ep.url):
                                        endpoint_inventory.add(js_ep)
                                for js_param in js_disc.discovered_parameters:
                                    param_inventory.add(js_param)
                        except Exception:
                            pass

                # Fingerprint technologies from crawl pages
                for page_url, page_data in crawl_result.page_results.items():
                    mock_resp = type("DummyResp", (), {"headers": {}, "body": page_data.raw_html})()
                    fingerprinter.analyze_response(mock_resp, meta_tags=page_data.meta_tags, scripts=page_data.scripts)

        # STEP 3.5: Attack Surface Intelligence & Prioritization
        detected_techs_list = [
            {"name": t.name, "category": t.category, "confidence": t.confidence, "evidence": t.evidence, "version": t.version}
            for t in fingerprinter.get_detected()
        ]

        attack_surface = AttackSurfaceBuilder.build(
            target_url=target.normalized_url,
            endpoints=endpoint_inventory.get_all(),
            parameters=param_inventory.get_all(),
            forms=getattr(crawl_result, "forms", []) if "crawl_result" in locals() else [],
            javascript_assets=list(getattr(crawl_result, "scripts", [])) if "crawl_result" in locals() else [],
            technologies=detected_techs_list,
        )

        discovered_endpoints = attack_surface.endpoints
        # Save all enriched discovered endpoints to database
        db.save_endpoints(context.scan_id, discovered_endpoints)

        if not quiet and verbose:
            render_attack_surface_summary(console, attack_surface)

        # STEP 4: Scanner Pipeline Execution
        scanner_engine = ScannerEngine()
        active_scanners = ScannerRegistry.filter(
            include=final_includes, exclude=final_excludes
        )

        if active_scanners and not context.is_cancelled:
            with console.status(f"[bold cyan]Running {len(active_scanners)} security analysis modules...[/bold cyan]", spinner="dots"):
                raw_obs, raw_findings = await scanner_engine.run(
                    scan_context=context,
                    endpoints=discovered_endpoints,
                    parameters=param_inventory.get_all(),
                    include_scanners=final_includes,
                    exclude_scanners=final_excludes,
                )

            # STEP 5: Finding Correlation & Confidence Scoring & Severity Engine
            correlation_engine = CorrelationEngine()
            findings = correlation_engine.correlate(
                observations=raw_obs,
                candidate_findings=raw_findings,
            )
            observations = raw_obs

            # Persist observations and correlated findings
            db.save_observations(context.scan_id, observations)
            db.save_findings(context.scan_id, findings)

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Scan interrupted safely.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130

    except ScopeViolationError as e:
        console.print(f"\n[bold red]{e}[/bold red]")
        status_label = "blocked"
        exit_code = 1

    except RequestTimeoutError as e:
        console.print(f"\n[bold yellow][!] Baseline probe timed out: {e}[/bold yellow]")
        status_label = "timeout"
        exit_code = 1

    except ConnectionFailedError as e:
        console.print(f"\n[bold red][ERROR] Connection failed: {e}[/bold red]")
        status_label = "unreachable"
        exit_code = 1

    except Exception as e:
        console.print(f"\n[bold red][ERROR] Unexpected scan error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1

    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    # STEP 6: Multi-Format Report Generation
    discovered_endpoints = endpoint_inventory.get_all()
    detected_techs = [
        {"name": t.name, "category": t.category, "confidence": t.confidence, "evidence": t.evidence, "version": t.version}
        for t in fingerprinter.get_detected()
    ]

    scan_meta = {
        "scan_id": context.scan_id,
        "target": target.model_dump(),
        "status": status_label,
        "profile": scan_profile,
        "technologies": detected_techs,
        "statistics": {
            "requests_sent": context.stats.requests_sent,
            "requests_successful": context.stats.requests_successful,
            "requests_failed": context.stats.requests_failed,
            "requests_blocked": context.stats.requests_blocked,
            "http_errors": context.stats.http_errors,
            "timeouts": context.stats.timeouts,
            "redirects": context.stats.redirects,
            "duration_seconds": context.stats.duration_seconds,
        },
    }

    target_format = (output_format or "terminal").lower()
    if output:
        out_lower = output.lower()
        if out_lower.endswith(".html"):
            target_format = "html"
        elif out_lower.endswith(".md") or out_lower.endswith(".markdown"):
            target_format = "markdown"
        elif out_lower.endswith(".json"):
            target_format = "json"

    # Auto-generate standard reports in output directory if format is terminal or standard
    reports_dir = Path(cfg.output_directory)
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        # Generate HTML report
        html_rep = generate_html_report(
            scan_data=scan_meta,
            findings=findings,
            endpoints=discovered_endpoints,
            technologies=detected_techs,
            statistics=scan_meta["statistics"],
        )
        html_path = reports_dir / "report.html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_rep)
        generated_reports.append(str(html_path))

        # Generate JSON report
        json_rep = generate_json_report(
            scan_data=scan_meta,
            findings=findings,
            endpoints=discovered_endpoints,
            technologies=detected_techs,
            statistics=scan_meta["statistics"],
        )
        json_path = reports_dir / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_rep)
        generated_reports.append(str(json_path))

        # Generate Markdown report
        md_rep = generate_markdown_report(
            scan_data=scan_meta,
            findings=findings,
            endpoints=discovered_endpoints,
            technologies=detected_techs,
            statistics=scan_meta["statistics"],
        )
        md_path = reports_dir / "report.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_rep)
        generated_reports.append(str(md_path))
    except Exception:
        pass

    # Custom output file requested by user
    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        rep_content = ""
        if target_format == "html":
            rep_content = generate_html_report(
                scan_data=scan_meta,
                findings=findings,
                endpoints=discovered_endpoints,
                technologies=detected_techs,
                statistics=scan_meta["statistics"],
            )
        elif target_format == "json":
            rep_content = generate_json_report(
                scan_data=scan_meta,
                findings=findings,
                endpoints=discovered_endpoints,
                technologies=detected_techs,
                statistics=scan_meta["statistics"],
            )
        elif target_format == "markdown":
            rep_content = generate_markdown_report(
                scan_data=scan_meta,
                findings=findings,
                endpoints=discovered_endpoints,
                technologies=detected_techs,
                statistics=scan_meta["statistics"],
            )

        if rep_content:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(rep_content)
            console.print(f"[green][+] Custom report saved to {out_path} ({target_format.upper()})[/green]")

    # STEP 7: Final Consolidated Dashboard
    if not quiet:
        console.print()
        render_scan_completion_dashboard(
            console=console,
            target_host=target.hostname,
            duration_str=context.stats.duration_formatted,
            requests_count=context.stats.requests_sent,
            endpoints_count=endpoint_inventory.total_count,
            parameters_count=param_inventory.total_count,
            findings=findings,
            reports=generated_reports if generated_reports else None,
        )

        if findings:
            render_top_findings(console, findings)

        render_statistics(console, context.stats)

    return exit_code


async def execute_crawl(
    target_url: str,
    depth: int = 3,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
    output_format: str = "table",
) -> int:
    """Execute asynchronous web crawling, link discovery, form parsing, and JS analysis."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(
        allowed_domains=target.scope,
        excluded_domains=exclude_list,
        excluded_paths=exclude_paths,
    )

    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)

    context = ScanContext(
        target=target,
        config=cfg,
        scope=scope_engine,
        rate_limiter=rate_limiter,
    )

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="crawling")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(
            f"[dim cyan]Crawl Depth:[/dim cyan] [bold white]{depth}[/bold white]  "
            f"[dim cyan]Concurrency:[/dim cyan] [bold white]{scan_threads}[/bold white]  "
            f"[dim cyan]Rate Limit:[/dim cyan] [bold white]{scan_rate} req/s[/bold white]"
        )
        console.print(f"[dim]Scan ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    fingerprinter = TechnologyFingerprinter()
    endpoint_inventory = EndpointInventory()
    param_inventory = ParameterInventory()

    exit_code = 0
    status_label = "completed"

    try:
        crawler = WebCrawler(context=context, max_depth=depth)

        with console.status(f"[bold cyan]Crawling target (depth: {depth})...[/bold cyan]", spinner="dots") as status_bar:
            def on_progress(url: str, d: int, total: int) -> None:
                status_bar.update(f"[bold cyan]Crawling [depth {d} | visited {total}]:[/bold cyan] [dim]{url[:60]}[/dim]")

            crawler.progress_callback = on_progress
            crawl_result = await crawler.crawl(target.normalized_url)

        # 1. Analyze Discovered JavaScript Assets
        if crawl_result.scripts and not context.is_cancelled:
            with console.status(f"[bold cyan]Analyzing {len(crawl_result.scripts)} JavaScript files...[/bold cyan]", spinner="dots"):
                for js_url in list(crawl_result.scripts):
                    if not context.scope.is_allowed(js_url):
                        continue
                    try:
                        js_resp = await http_engine.get(js_url)
                        if js_resp.is_success and js_resp.body:
                            js_disc = extract_endpoints_from_js(js_resp.body, js_url, target.base_url())
                            for js_ep in js_disc.discovered_endpoints:
                                if context.scope.is_allowed(js_ep.url):
                                    crawler._add_endpoint(js_ep)
                            for js_param in js_disc.discovered_parameters:
                                crawler._add_parameter(js_param)
                    except Exception:
                        pass

        # 2. Perform Passive Technology Fingerprinting
        for page_url, page_data in crawl_result.page_results.items():
            mock_resp = type("DummyResp", (), {"headers": {}, "body": page_data.raw_html})()
            fingerprinter.analyze_response(
                response=mock_resp,
                meta_tags=page_data.meta_tags,
                scripts=page_data.scripts,
            )

        # 3. Consolidate inventory
        for ep in crawl_result.endpoints:
            endpoint_inventory.add(ep)
        for p in crawl_result.parameters:
            param_inventory.add(p)

        # Save to database
        db.save_endpoints(context.scan_id, endpoint_inventory.get_all())

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Scan interrupted safely.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130

    except Exception as e:
        console.print(f"\n[bold red][ERROR] Crawler execution failure: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1

    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    # Output Presentation
    if not quiet:
        console.print()
        detected_techs = fingerprinter.get_detected()
        render_attack_surface_dashboard(
            console=console,
            urls_count=len(crawl_result.visited_urls) if 'crawl_result' in locals() else 0,
            endpoints_count=endpoint_inventory.total_count,
            parameters_count=param_inventory.total_count,
            forms_count=len(crawl_result.forms) if 'crawl_result' in locals() else 0,
            js_count=len(crawl_result.scripts) if 'crawl_result' in locals() else 0,
            apis_count=endpoint_inventory.api_count,
            tech_count=len(detected_techs),
        )

        if detected_techs:
            console.print()
            render_technologies_table(console, detected_techs)

        if 'crawl_result' in locals() and crawl_result.forms:
            console.print()
            render_forms_table(console, crawl_result.forms)

        if endpoint_inventory.total_count > 0:
            console.print()
            render_endpoints_table(console, endpoint_inventory.get_all())

        console.print()
        render_statistics(console, context.stats)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "scan_id": context.scan_id,
            "target": target.model_dump(),
            "status": status_label,
            "attack_surface": {
                "urls_visited": list(crawl_result.visited_urls) if 'crawl_result' in locals() else [],
                "endpoints_count": endpoint_inventory.total_count,
                "parameters_count": param_inventory.total_count,
                "forms_count": len(crawl_result.forms) if 'crawl_result' in locals() else 0,
                "apis_count": endpoint_inventory.api_count,
                "endpoints": [ep.model_dump(mode="json") for ep in endpoint_inventory.get_all()],
                "parameters": [p.model_dump(mode="json") for p in param_inventory.get_all()],
                "technologies": [
                    {
                        "name": t.name,
                        "category": t.category,
                        "confidence": t.confidence,
                        "evidence": t.evidence,
                        "version": t.version,
                    }
                    for t in fingerprinter.get_detected()
                ],
            },
            "statistics": {
                "requests_sent": context.stats.requests_sent,
                "requests_successful": context.stats.requests_successful,
                "requests_failed": context.stats.requests_failed,
                "requests_blocked": context.stats.requests_blocked,
                "http_errors": context.stats.http_errors,
                "timeouts": context.stats.timeouts,
                "duration_seconds": context.stats.duration_seconds,
            },
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        console.print(f"[green][+] Crawl results saved to {out_path}[/green]")

    return exit_code


async def execute_recon(
    target_url: str,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
) -> int:
    """Execute target reconnaissance: robots, sitemaps, headers, and technology fingerprinting."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(
        allowed_domains=target.scope,
        excluded_domains=exclude_list,
    )

    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)

    context = ScanContext(
        target=target,
        config=cfg,
        scope=scope_engine,
        rate_limiter=rate_limiter,
    )

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="recon")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(f"[dim]Recon Scan ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    fingerprinter = TechnologyFingerprinter()
    discovered_routes: List[str] = []

    exit_code = 0
    status_label = "completed"

    try:
        with console.status("[bold cyan]Executing reconnaissance probes...[/bold cyan]", spinner="dots"):
            # 1. Probe Root Page
            root_resp = await http_engine.get(
                target.normalized_url,
                headers=parsed_headers,
                cookies=parsed_cookies,
            )
            fingerprinter.analyze_response(root_resp)

            # 2. Check /robots.txt
            parsed_root = urlparse(target.normalized_url)
            base_root = f"{parsed_root.scheme}://{parsed_root.netloc}"
            robots_url = f"{base_root}/robots.txt"

            if context.scope.is_allowed(robots_url):
                try:
                    rob_resp = await http_engine.get(robots_url)
                    if rob_resp.is_success and "text" in rob_resp.content_type.lower():
                        rob_res = parse_robots_txt(rob_resp.body, base_root)
                        discovered_routes.extend(rob_res.discovered_urls)
                        for sm in rob_res.sitemaps:
                            if context.scope.is_allowed(sm):
                                try:
                                    sm_resp = await http_engine.get(sm)
                                    if sm_resp.is_success:
                                        sm_urls = parse_sitemap_xml(sm_resp.body, base_root)
                                        discovered_routes.extend(sm_urls)
                                except Exception:
                                    pass
                except Exception:
                    pass

            # 3. Check /sitemap.xml directly
            sitemap_url = f"{base_root}/sitemap.xml"
            if context.scope.is_allowed(sitemap_url) and sitemap_url not in discovered_routes:
                try:
                    sm_resp = await http_engine.get(sitemap_url)
                    if sm_resp.is_success:
                        sm_urls = parse_sitemap_xml(sm_resp.body, base_root)
                        discovered_routes.extend(sm_urls)
                except Exception:
                    pass

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Scan interrupted safely.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130

    except Exception as e:
        console.print(f"\n[bold red][ERROR] Recon probe error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1

    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    if not quiet:
        console.print()
        detected_techs = fingerprinter.get_detected()
        if detected_techs:
            render_technologies_table(console, detected_techs)
            console.print()

        if discovered_routes:
            table = Table(title="[bold cyan]ROBOTS & SITEMAP ROUTES[/bold cyan]", border_style="dim")
            table.add_column("Discovered Route", style="bold white")
            for r in discovered_routes[:15]:
                table.add_row(r)
            if len(discovered_routes) > 15:
                table.caption = f"[dim]Showing 15 of {len(discovered_routes)} discovered routes[/dim]"
            console.print(table)
            console.print()

        render_statistics(console, context.stats)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "scan_id": context.scan_id,
            "target": target.model_dump(),
            "status": status_label,
            "technologies": [
                {
                    "name": t.name,
                    "category": t.category,
                    "confidence": t.confidence,
                    "evidence": t.evidence,
                    "version": t.version,
                }
                for t in fingerprinter.get_detected()
            ],
            "discovered_routes": discovered_routes,
            "statistics": {
                "requests_sent": context.stats.requests_sent,
                "requests_successful": context.stats.requests_successful,
                "duration_seconds": context.stats.duration_seconds,
            },
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        console.print(f"[green][+] Recon results saved to {out_path}[/green]")

    return exit_code


def cmd_version() -> None:
    """Print VulnForge version information."""
    console.print(f"[bold cyan]VulnForge[/bold cyan] version [bold white]{__version__}[/bold white]")
    console.print("[dim]Web Security Assessment Engine (Authorized Testing Only)[/dim]")


def cmd_scanners() -> None:
    """Display the registry of registered security assessment scanners."""
    render_banner(console, compact=True)
    scanners = ScannerRegistry.list()
    render_scanner_registry_table(console, scanners)


def cmd_history(limit: int = 20) -> None:
    """List historical scan sessions from SQLite database."""
    render_banner(console, compact=True)
    cfg = load_config()
    db = DatabaseManager(cfg.database_path)
    scans = db.list_scans(limit=limit)

    if not scans:
        console.print("[dim]No past scan records found in database.[/dim]")
        return

    table = Table(title="[bold cyan]SCAN HISTORY[/bold cyan]", border_style="dim")
    table.add_column("Scan ID", style="dim", width=14)
    table.add_column("Target URL", style="bold white")
    table.add_column("Profile", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Requests", justify="right")
    table.add_column("Findings", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Date", style="dim")

    for scan in scans:
        scan_id_short = scan["id"][:8] + "..." if scan.get("id") else "-"
        status_color = "green" if scan.get("status") == "completed" else "yellow"
        req_summary = f"{scan.get('requests_sent', 0)} ({scan.get('requests_successful', 0)} ok)"
        dur = f"{scan.get('duration_seconds', 0.0):.1f}s"

        findings_count = scan.get("findings_count", 0)
        crit_count = scan.get("critical_count", 0)
        high_count = scan.get("high_count", 0)
        if crit_count or high_count:
            finding_summary = f"[bold red]{findings_count}[/bold red] [dim](C:{crit_count}/H:{high_count})[/dim]"
        elif findings_count > 0:
            finding_summary = f"[yellow]{findings_count}[/yellow]"
        else:
            finding_summary = "[dim]0[/dim]"

        table.add_row(
            scan_id_short,
            scan.get("target_url", "-"),
            scan.get("profile", "safe"),
            f"[{status_color}]{scan.get('status', '-')}[/{status_color}]",
            req_summary,
            finding_summary,
            dur,
            str(scan.get("created_at", "-"))[:19],
        )

    console.print(table)


def cmd_show(scan_id: Optional[str] = None) -> None:
    """Display comprehensive details and findings of a specific or latest scan."""
    render_banner(console, compact=True)
    cfg = load_config()
    db = DatabaseManager(cfg.database_path)

    if scan_id:
        scan = db.get_scan(scan_id)
    else:
        scan = db.get_latest_scan()

    if not scan:
        target_name = f"ID '{scan_id}'" if scan_id else "Latest scan"
        console.print(f"[bold red][ERROR][/bold red] {target_name} not found in database.")
        return

    actual_scan_id = scan["id"]
    findings_raw = db.get_findings(actual_scan_id)

    console.print(f"[bold cyan]Scan ID:[/bold cyan] [bold white]{actual_scan_id}[/bold white]")
    console.print(f"[bold cyan]Target:[/bold cyan] [bold white]{scan.get('target_url')}[/bold white]")
    console.print(f"[bold cyan]Status:[/bold cyan] {scan.get('status')}  |  [bold cyan]Duration:[/bold cyan] {scan.get('duration_seconds', 0.0):.1f}s")
    console.print(f"[bold cyan]Findings:[/bold cyan] {len(findings_raw)}\n")

    if not findings_raw:
        console.print("[dim]No security findings recorded for this session.[/dim]\n")
        return

    for idx, f_dict in enumerate(findings_raw, 1):
        finding_obj = Finding(
            id=f_dict["id"],
            scanner=f_dict["scanner"],
            category=f_dict["category"],
            title=f_dict["title"],
            severity=f_dict["severity"],
            confidence=f_dict["confidence"],
            status=f_dict["status"],
            endpoint_url=f_dict["endpoint_url"],
            parameter_name=f_dict["parameter_name"],
            description=f_dict["description"] or "",
            evidence=f_dict["evidence"] or "",
            recommendation=f_dict["recommendation"] or "",
        )
        render_finding_detail(console, finding_obj)


def cmd_stats(scan_id: Optional[str] = None) -> None:
    """Display internal scan performance, request counts, and telemetry metrics."""
    render_banner(console, compact=True)
    cfg = load_config()
    db = DatabaseManager(cfg.database_path)

    if scan_id:
        scan = db.get_scan(scan_id)
    else:
        scan = db.get_latest_scan()

    if not scan:
        target_name = f"ID '{scan_id}'" if scan_id else "Latest scan"
        console.print(f"[bold red][ERROR][/bold red] {target_name} not found in database.")
        return

    actual_scan_id = scan["id"]
    findings_raw = db.get_findings(actual_scan_id)
    endpoints_raw = db.get_endpoints(actual_scan_id)
    observations_raw = db.get_observations(actual_scan_id)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold white", width=24)
    grid.add_column(style="cyan", justify="right")
    grid.add_column(style="bold white", width=24)
    grid.add_column(style="cyan", justify="right")

    req_sent = scan.get("requests_sent", 0)
    req_succ = scan.get("requests_successful", 0)
    req_fail = scan.get("requests_failed", 0)
    req_block = scan.get("requests_blocked", 0)
    dur = scan.get("duration_seconds", 0.0)

    grid.add_row("Requests Sent", str(req_sent), "Requests Successful", f"[green]{req_succ}[/green]")
    grid.add_row("Requests Failed", f"[red]{req_fail}[/red]" if req_fail else "0", "Requests Blocked", f"[yellow]{req_block}[/yellow]" if req_block else "0")
    grid.add_row("Endpoints Mapped", str(len(endpoints_raw)), "Observations Recorded", str(len(observations_raw)))
    grid.add_row("Findings Synthesized", str(len(findings_raw)), "Execution Duration", f"{dur:.2f}s")
    grid.add_row("Scan Status", str(scan.get("status", "unknown")).upper(), "Scan Profile", str(scan.get("profile", "safe")))

    panel = Panel(
        grid,
        title=f"[bold cyan]SCAN TELEMETRY & EXECUTION METRICS ({actual_scan_id[:12]})[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()



def cmd_diff(scan_id_1: str, scan_id_2: str) -> None:
    """Compare findings between two scan sessions (scan_1: baseline, scan_2: candidate)."""
    render_banner(console, compact=True)
    cfg = load_config()
    db = DatabaseManager(cfg.database_path)

    scan1 = db.get_scan(scan_id_1)
    scan2 = db.get_scan(scan_id_2)

    if not scan1:
        console.print(f"[bold red][ERROR][/bold red] Baseline scan '{scan_id_1}' not found.")
        return
    if not scan2:
        console.print(f"[bold red][ERROR][/bold red] Target scan '{scan_id_2}' not found.")
        return

    findings_1 = db.get_findings(scan_id_1)
    findings_2 = db.get_findings(scan_id_2)

    def finding_key(f: Dict[str, Any]) -> str:
        endpoint = f.get("endpoint_url", "")
        param = (f.get("parameter_name") or "").strip().lower()
        title = (f.get("title") or "").strip().lower()
        return f"{endpoint}::{param}::{title}"

    f1_map = {finding_key(f): f for f in findings_1}
    f2_map = {finding_key(f): f for f in findings_2}

    new_findings = [f for k, f in f2_map.items() if k not in f1_map]
    resolved_findings = [f for k, f in f1_map.items() if k not in f2_map]
    unchanged_findings = [f for k, f in f2_map.items() if k in f1_map]

    diff_data = {
        "new": new_findings,
        "resolved": resolved_findings,
        "unchanged": unchanged_findings,
    }

    console.print(f"[dim]Baseline: {scan_id_1[:8]}... ({scan1.get('target_url')})[/dim]")
    console.print(f"[dim]Candidate: {scan_id_2[:8]}... ({scan2.get('target_url')})[/dim]\n")

    render_scan_diff_table(console, diff_data)
    console.print(
        f"\n[bold green]New:[/bold green] {len(new_findings)}  |  "
        f"[bold cyan]Resolved:[/bold cyan] {len(resolved_findings)}  |  "
        f"[dim]Unchanged:[/dim] {len(unchanged_findings)}\n"
    )


def cmd_regression(
    baseline_id: str,
    current_id: str,
    output: Optional[str] = None,
    format_opt: str = "terminal",
) -> int:
    """Analyze security regression, resolved flaws, reopened vulnerabilities, and attack surface deltas."""
    render_banner(console, compact=True)
    cfg = load_config()
    db = DatabaseManager(cfg.database_path)

    scan_base = db.get_scan(baseline_id)
    scan_curr = db.get_scan(current_id)

    if not scan_base:
        console.print(f"[bold red][ERROR][/bold red] Baseline scan '{baseline_id}' not found.")
        return 1
    if not scan_curr:
        console.print(f"[bold red][ERROR][/bold red] Candidate scan '{current_id}' not found.")
        return 1

    findings_base_raw = db.get_findings(baseline_id)
    findings_curr_raw = db.get_findings(current_id)

    findings_base = [
        Finding(
            id=f["id"],
            scanner=f["scanner"],
            category=f["category"],
            title=f["title"],
            severity=f["severity"],
            confidence=f["confidence"],
            status=f["status"],
            endpoint_url=f["endpoint_url"],
            parameter_name=f["parameter_name"],
            description=f.get("description") or "",
            evidence=f.get("evidence") or "",
            recommendation=f.get("recommendation") or "",
        )
        for f in findings_base_raw
    ]

    findings_curr = [
        Finding(
            id=f["id"],
            scanner=f["scanner"],
            category=f["category"],
            title=f["title"],
            severity=f["severity"],
            confidence=f["confidence"],
            status=f["status"],
            endpoint_url=f["endpoint_url"],
            parameter_name=f["parameter_name"],
            description=f.get("description") or "",
            evidence=f.get("evidence") or "",
            recommendation=f.get("recommendation") or "",
        )
        for f in findings_curr_raw
    ]

    endpoints_base = [ep.get("path", "") for ep in db.get_endpoints(baseline_id)]
    endpoints_curr = [ep.get("path", "") for ep in db.get_endpoints(current_id)]

    engine = SecurityRegressionEngine()
    report = engine.evaluate_regression(
        baseline_scan_id=baseline_id,
        current_scan_id=current_id,
        baseline_findings=findings_base,
        current_findings=findings_curr,
        baseline_endpoints=endpoints_base,
        current_endpoints=endpoints_curr,
        target_url=scan_curr.get("target_url") or scan_base.get("target_url") or "",
    )

    if format_opt == "terminal":
        render_regression_report(console, report)
    elif format_opt == "json":
        console.print(report.model_dump_json(indent=2))

    if output:
        out_p = Path(output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
        console.print(f"[green][+] Regression report saved to {out_p}[/green]")

    return 1 if report.has_blocking_regressions else 0



def cmd_config_show() -> None:
    """Display active configuration settings."""
    cfg = load_config()
    table = Table(title="[bold cyan]ACTIVE CONFIGURATION[/bold cyan]", border_style="dim")
    table.add_column("Setting", style="bold white")
    table.add_column("Value", style="cyan")

    for k, v in cfg.to_dict().items():
        table.add_row(k, str(v))

    console.print(table)
    console.print(f"[dim]Config file: {get_default_config_path()}[/dim]")


def cmd_config_init() -> None:
    """Create default configuration file if not exists."""
    cfg_path = get_default_config_path()
    if cfg_path.exists():
        console.print(f"[yellow][!] Config file already exists at {cfg_path}[/yellow]")
        return
    cfg = VulnForgeConfig()
    saved = save_config(cfg)
    console.print(f"[green][+] Created default configuration file at {saved}[/green]")


async def execute_surface(
    target_url: str,
    depth: int = 3,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
) -> int:
    """Analyze, classify, prioritize, and summarize the attack surface of the target."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(
        allowed_domains=target.scope,
        excluded_domains=exclude_list,
        excluded_paths=exclude_paths,
    )

    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)

    context = ScanContext(
        target=target,
        config=cfg,
        scope=scope_engine,
        rate_limiter=rate_limiter,
    )

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="mapping_surface")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(
            f"[dim cyan]Crawl Depth:[/dim cyan] [bold white]{depth}[/bold white]  "
            f"[dim cyan]Concurrency:[/dim cyan] [bold white]{scan_threads}[/bold white]  "
            f"[dim cyan]Rate Limit:[/dim cyan] [bold white]{scan_rate} req/s[/bold white]"
        )
        console.print(f"[dim]Session ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    fingerprinter = TechnologyFingerprinter()
    endpoint_inventory = EndpointInventory()
    param_inventory = ParameterInventory()

    exit_code = 0
    status_label = "completed"

    try:
        # STEP 1: Baseline Probe & Recon
        with console.status("[bold cyan]Probing target baseline...[/bold cyan]", spinner="dots"):
            root_resp = await http_engine.get(
                target.normalized_url,
                headers=parsed_headers,
                cookies=parsed_cookies,
            )

        root_ep = Endpoint.from_url(
            target.normalized_url,
            method="GET",
            source="probe",
            status_code=root_resp.status_code,
            content_type=root_resp.content_type,
        )
        endpoint_inventory.add(root_ep)
        for p in root_ep.parameters:
            param_inventory.add(p)

        fingerprinter.analyze_response(root_resp)

        # STEP 2: Reconnaissance (robots.txt and sitemap.xml)
        if not context.is_cancelled:
            with console.status("[bold cyan]Inspecting robots.txt and sitemaps...[/bold cyan]", spinner="dots"):
                parsed_root = urlparse(target.normalized_url)
                base_root = f"{parsed_root.scheme}://{parsed_root.netloc}"
                robots_url = f"{base_root}/robots.txt"

                if context.scope.is_allowed(robots_url):
                    try:
                        rob_resp = await http_engine.get(robots_url)
                        if rob_resp.is_success and "text" in rob_resp.content_type.lower():
                            rob_res = parse_robots_txt(rob_resp.body, base_root)
                            for r_url in rob_res.discovered_urls:
                                if context.scope.is_allowed(r_url):
                                    ep = Endpoint.from_url(r_url, method="GET", source="robots.txt")
                                    endpoint_inventory.add(ep)
                                    for p in ep.parameters:
                                        param_inventory.add(p)
                            for sm in rob_res.sitemaps:
                                if context.scope.is_allowed(sm):
                                    try:
                                        sm_resp = await http_engine.get(sm)
                                        if sm_resp.is_success:
                                            for sm_url in parse_sitemap_xml(sm_resp.body, base_root):
                                                if context.scope.is_allowed(sm_url):
                                                    ep = Endpoint.from_url(sm_url, method="GET", source="sitemap.xml")
                                                    endpoint_inventory.add(ep)
                                    except Exception:
                                        pass
                    except Exception:
                        pass

        # STEP 3: Web Crawling & Endpoint Discovery
        crawler = WebCrawler(context=context, max_depth=depth)
        crawl_result = None
        if depth > 0 and not context.is_cancelled:
            with console.status(f"[bold cyan]Crawling endpoints (depth: {depth})...[/bold cyan]", spinner="dots") as status_bar:
                def on_progress(url: str, d: int, total: int) -> None:
                    status_bar.update(f"[bold cyan]Crawling [depth {d} | visited {total}]:[/bold cyan] [dim]{url[:60]}[/dim]")

                crawler.progress_callback = on_progress
                crawl_result = await crawler.crawl(target.normalized_url)

                for ep in crawl_result.endpoints:
                    endpoint_inventory.add(ep)
                for p in crawl_result.parameters:
                    param_inventory.add(p)

                # Analyze JavaScript Assets
                for js_url in list(crawl_result.scripts)[:15]:
                    if context.scope.is_allowed(js_url):
                        try:
                            js_resp = await http_engine.get(js_url)
                            if js_resp.is_success and js_resp.body:
                                js_disc = extract_endpoints_from_js(js_resp.body, js_url, target.base_url())
                                for js_ep in js_disc.discovered_endpoints:
                                    if context.scope.is_allowed(js_ep.url):
                                        endpoint_inventory.add(js_ep)
                                for js_param in js_disc.discovered_parameters:
                                    param_inventory.add(js_param)
                        except Exception:
                            pass

                # Fingerprint technologies from crawl pages
                for page_url, page_data in crawl_result.page_results.items():
                    mock_resp = type("DummyResp", (), {"headers": {}, "body": page_data.raw_html})()
                    fingerprinter.analyze_response(mock_resp, meta_tags=page_data.meta_tags, scripts=page_data.scripts)

        # STEP 4: Build Attack Surface Intelligence
        detected_techs = [
            {"name": t.name, "category": t.category, "confidence": t.confidence, "evidence": t.evidence, "version": t.version}
            for t in fingerprinter.get_detected()
        ]

        surface = AttackSurfaceBuilder.build(
            target_url=target.normalized_url,
            endpoints=endpoint_inventory.get_all(),
            parameters=param_inventory.get_all(),
            forms=getattr(crawl_result, "forms", []) if crawl_result else [],
            javascript_assets=list(getattr(crawl_result, "scripts", [])) if crawl_result else [],
            technologies=detected_techs,
        )

        # Persist enriched endpoints and parameters
        db.save_endpoints(context.scan_id, surface.endpoints)

        # STEP 5: Render Dashboards & Tables
        if not quiet:
            render_attack_surface_summary(console, surface)
            render_endpoint_priority_table(console, surface.endpoints, limit=15)
            render_parameter_classification_table(console, surface.parameters, limit=15)
            if detected_techs:
                render_technologies_table(console, fingerprinter.get_detected())

        # STEP 6: Optional Export
        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(surface.model_dump_json(indent=2))
            console.print(f"[green][+] Attack surface map exported to {out_path}[/green]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Attack surface discovery interrupted safely.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130
    except Exception as e:
        console.print(f"\n[bold red][ERROR] Surface discovery error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1
    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    return exit_code


async def execute_graph(
    target_url: str,
    depth: int = 3,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
) -> int:
    """Discover and render the Attack Surface Graph topology and hierarchy for the target."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(
        allowed_domains=target.scope,
        excluded_domains=exclude_list,
        excluded_paths=exclude_paths,
    )

    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)

    context = ScanContext(
        target=target,
        config=cfg,
        scope=scope_engine,
        rate_limiter=rate_limiter,
    )

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="mapping_graph")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(
            f"[dim cyan]Crawl Depth:[/dim cyan] [bold white]{depth}[/bold white]  "
            f"[dim cyan]Concurrency:[/dim cyan] [bold white]{scan_threads}[/bold white]  "
            f"[dim cyan]Rate Limit:[/dim cyan] [bold white]{scan_rate} req/s[/bold white]"
        )
        console.print(f"[dim]Graph Session ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    fingerprinter = TechnologyFingerprinter()
    endpoint_inventory = EndpointInventory()
    param_inventory = ParameterInventory()

    exit_code = 0
    status_label = "completed"

    try:
        # STEP 1: Baseline Probe & Recon
        with console.status("[bold cyan]Probing target baseline...[/bold cyan]", spinner="dots"):
            root_resp = await http_engine.get(
                target.normalized_url,
                headers=parsed_headers,
                cookies=parsed_cookies,
            )

        root_ep = Endpoint.from_url(
            target.normalized_url,
            method="GET",
            source="probe",
            status_code=root_resp.status_code,
            content_type=root_resp.content_type,
        )
        endpoint_inventory.add(root_ep)
        for p in root_ep.parameters:
            param_inventory.add(p)

        fingerprinter.analyze_response(root_resp)

        # STEP 2: Reconnaissance (robots.txt and sitemap.xml)
        if not context.is_cancelled:
            with console.status("[bold cyan]Inspecting robots.txt and sitemaps...[/bold cyan]", spinner="dots"):
                parsed_root = urlparse(target.normalized_url)
                base_root = f"{parsed_root.scheme}://{parsed_root.netloc}"
                robots_url = f"{base_root}/robots.txt"

                if context.scope.is_allowed(robots_url):
                    try:
                        rob_resp = await http_engine.get(robots_url)
                        if rob_resp.is_success and "text" in rob_resp.content_type.lower():
                            rob_res = parse_robots_txt(rob_resp.body, base_root)
                            for r_url in rob_res.discovered_urls:
                                if context.scope.is_allowed(r_url):
                                    ep = Endpoint.from_url(r_url, method="GET", source="robots.txt")
                                    endpoint_inventory.add(ep)
                                    for p in ep.parameters:
                                        param_inventory.add(p)
                            for sm in rob_res.sitemaps:
                                if context.scope.is_allowed(sm):
                                    try:
                                        sm_resp = await http_engine.get(sm)
                                        if sm_resp.is_success:
                                            for sm_url in parse_sitemap_xml(sm_resp.body, base_root):
                                                if context.scope.is_allowed(sm_url):
                                                    ep = Endpoint.from_url(sm_url, method="GET", source="sitemap.xml")
                                                    endpoint_inventory.add(ep)
                                    except Exception:
                                        pass
                    except Exception:
                        pass

        # STEP 3: Web Crawling & Endpoint Discovery
        crawler = WebCrawler(context=context, max_depth=depth)
        crawl_result = None
        if depth > 0 and not context.is_cancelled:
            with console.status(f"[bold cyan]Crawling endpoints for graph (depth: {depth})...[/bold cyan]", spinner="dots") as status_bar:
                def on_progress(url: str, d: int, total: int) -> None:
                    status_bar.update(f"[bold cyan]Graph Mapping [depth {d} | visited {total}]:[/bold cyan] [dim]{url[:60]}[/dim]")

                crawler.progress_callback = on_progress
                crawl_result = await crawler.crawl(target.normalized_url)

                for ep in crawl_result.endpoints:
                    endpoint_inventory.add(ep)
                for p in crawl_result.parameters:
                    param_inventory.add(p)

                # Analyze JavaScript Assets
                for js_url in list(crawl_result.scripts)[:15]:
                    if context.scope.is_allowed(js_url):
                        try:
                            js_resp = await http_engine.get(js_url)
                            if js_resp.is_success and js_resp.body:
                                js_disc = extract_endpoints_from_js(js_resp.body, js_url, target.base_url())
                                for js_ep in js_disc.discovered_endpoints:
                                    if context.scope.is_allowed(js_ep.url):
                                        endpoint_inventory.add(js_ep)
                                for js_param in js_disc.discovered_parameters:
                                    param_inventory.add(js_param)
                        except Exception:
                            pass

                for page_url, page_data in crawl_result.page_results.items():
                    mock_resp = type("DummyResp", (), {"headers": {}, "body": page_data.raw_html})()
                    fingerprinter.analyze_response(mock_resp, meta_tags=page_data.meta_tags, scripts=page_data.scripts)

        # STEP 4: Build Attack Surface & Graph
        detected_techs = [
            {"name": t.name, "category": t.category, "confidence": t.confidence, "evidence": t.evidence, "version": t.version}
            for t in fingerprinter.get_detected()
        ]

        surface = AttackSurfaceBuilder.build(
            target_url=target.normalized_url,
            endpoints=endpoint_inventory.get_all(),
            parameters=param_inventory.get_all(),
            forms=getattr(crawl_result, "forms", []) if crawl_result else [],
            javascript_assets=list(getattr(crawl_result, "scripts", [])) if crawl_result else [],
            technologies=detected_techs,
        )

        # Build Graph
        graph = AttackSurfaceGraph.from_attack_surface(surface)

        # Persist enriched endpoints and parameters
        db.save_endpoints(context.scan_id, surface.endpoints)

        # STEP 5: Render Graph UI
        if not quiet:
            render_attack_surface_graph(console, graph)

        # STEP 6: Optional Export
        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(graph.model_dump_json(indent=2))
            console.print(f"[green][+] Attack surface graph exported to {out_path}[/green]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Graph discovery interrupted safely.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130
    except Exception as e:
        console.print(f"\n[bold red][ERROR] Graph discovery error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1
    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    return exit_code


async def execute_api(
    target_url: str,
    spec_file: Optional[str] = None,
    depth: int = 2,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
) -> int:
    """Assess and discover API endpoints, import OpenAPI/Swagger specs, and detect undocumented routes."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(allowed_domains=target.scope, excluded_domains=exclude_list)
    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)
    context = ScanContext(target=target, config=cfg, scope=scope_engine, rate_limiter=rate_limiter)

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="api_assessment")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(f"[dim]API Assessment Session ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    exit_code = 0
    status_label = "completed"

    try:
        spec: Optional[APISpec] = None
        spec_source_url = ""

        # 1. Load or Auto-detect Spec
        if spec_file:
            with open(spec_file, "r", encoding="utf-8") as f:
                spec_json = json.load(f)
                spec = OpenAPIParser.parse(spec_json, base_url=target.normalized_url)
                console.print(f"[green][+] Loaded API specification from {spec_file} ({len(spec.routes)} routes)[/green]")
        else:
            with console.status("[bold cyan]Probing for OpenAPI / Swagger specifications...[/bold cyan]", spinner="dots"):
                spec_res = await OpenAPIScanner.auto_detect_spec(http_engine, target.normalized_url)
                if spec_res:
                    spec_source_url, spec = spec_res
                    console.print(f"[green][+] Discovered API specification at {spec_source_url} ({len(spec.routes)} routes)[/green]")
                else:
                    console.print("[dim]No OpenAPI / Swagger specification auto-discovered on standard endpoints.[/dim]")

        # 2. Lightweight Crawl for route comparison
        crawler = WebCrawler(context=context, max_depth=depth)
        crawl_result = await crawler.crawl(target.normalized_url)

        discovered_endpoints = crawl_result.endpoints if crawl_result else []

        # If spec found, convert routes to endpoints and save to DB
        if spec:
            spec_eps = OpenAPIScanner.spec_to_endpoints(spec, target.normalized_url)
            db.save_endpoints(context.scan_id, spec_eps)

        # 3. Analyze API Security
        if spec:
            analysis = OpenAPIScanner.analyze_api_security(spec, discovered_endpoints, target.normalized_url)
        else:
            analysis = APIAnalysisResult(
                target_url=target.normalized_url,
                documented_endpoints_count=0,
                discovered_endpoints_count=len(discovered_endpoints),
            )

        # 4. Render UI
        if not quiet:
            render_api_analysis_table(console, analysis)

        # 5. Export
        if output:
            out_p = Path(output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(analysis.model_dump_json(indent=2))
            console.print(f"[green][+] API analysis report saved to {out_p}[/green]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] API assessment cancelled.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130
    except Exception as e:
        console.print(f"\n[bold red][ERROR] API assessment error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1
    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    return exit_code


async def execute_graphql(
    target_url: str,
    scope_list: Optional[List[str]] = None,
    exclude_list: Optional[List[str]] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    verbose: bool = False,
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
) -> int:
    """Assess GraphQL endpoint, execute non-destructive introspection audit, and identify schema exposures."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    scan_threads = threads or cfg.default_threads
    scan_rate = rate if rate is not None else cfg.default_rate
    scan_timeout = timeout if timeout is not None else cfg.default_timeout
    scan_ua = user_agent or cfg.default_user_agent

    try:
        target = Target.from_url(
            target_url,
            scope=scope_list,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(allowed_domains=target.scope, excluded_domains=exclude_list)
    rate_limiter = RateLimiter(rate=scan_rate, concurrency=scan_threads)
    context = ScanContext(target=target, config=cfg, scope=scope_engine, rate_limiter=rate_limiter)

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="graphql_assessment")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(f"[dim]GraphQL Session ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=scan_timeout,
        user_agent=scan_ua,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    exit_code = 0
    status_label = "completed"

    try:
        # 1. Detect or use GraphQL endpoint
        graphql_endpoint = target.normalized_url
        if not ("graphql" in target.normalized_url.lower() or "query" in target.normalized_url.lower()):
            with console.status("[bold cyan]Searching for GraphQL endpoints...[/bold cyan]", spinner="dots"):
                detected = await GraphQLAnalyzer.detect_graphql_endpoint(http_engine, target.normalized_url)
                if detected:
                    graphql_endpoint = detected
                    console.print(f"[green][+] Discovered GraphQL endpoint at {graphql_endpoint}[/green]")
                else:
                    console.print("[dim]No GraphQL endpoint auto-discovered at common routes. Assessing target URL directly.[/dim]")

        # 2. Run Introspection and Schema Analysis
        with console.status("[bold cyan]Auditing GraphQL schema and introspection...[/bold cyan]", spinner="dots"):
            analysis = await GraphQLAnalyzer.analyze_graphql(http_engine, graphql_endpoint)

        # 3. Generate Findings
        findings = GraphQLAnalyzer.generate_findings(analysis)
        if findings:
            db.save_findings(context.scan_id, findings)

        # 4. Render UI
        if not quiet:
            render_graphql_analysis_table(console, analysis)
            if findings:
                render_findings_table(console, findings)

        # 5. Export
        if output:
            out_p = Path(output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(analysis.model_dump_json(indent=2))
            console.print(f"[green][+] GraphQL analysis report saved to {out_p}[/green]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] GraphQL assessment cancelled.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130
    except Exception as e:
        console.print(f"\n[bold red][ERROR] GraphQL assessment error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1
    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    return exit_code


def execute_token(
    token_input: str,
    output: Optional[str] = None,
    quiet: bool = False,
) -> int:
    """Analyze a JSON Web Token (JWT) or raw string for cryptographic and configuration flaws."""
    if not quiet:
        render_banner(console, compact=True)

    analysis = JWTAnalyzer.analyze_token(token_input)

    if not quiet:
        render_jwt_analysis_table(console, analysis)
        if analysis.findings:
            render_findings_table(console, analysis.findings)

    if output:
        out_p = Path(output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(analysis.model_dump_json(indent=2))
        console.print(f"[green][+] JWT analysis report saved to {out_p}[/green]")

    return 1 if any(f.severity.value in ("CRITICAL", "HIGH") for f in analysis.findings) else 0


async def execute_websocket(
    target_url: str,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    quiet: bool = False,
    allow_private: bool = True,
    output: Optional[str] = None,
) -> int:
    """Perform WebSocket protocol, origin validation, and CSWSH security analysis."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    try:
        target = Target.from_url(
            target_url,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(allowed_domains=target.scope)
    rate_limiter = RateLimiter(rate=cfg.default_rate, concurrency=cfg.default_threads)
    context = ScanContext(target=target, config=cfg, scope=scope_engine, rate_limiter=rate_limiter)

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="websocket_assessment")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(f"[dim]WebSocket Session ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=cfg.default_timeout,
        user_agent=user_agent or cfg.default_user_agent,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    exit_code = 0
    status_label = "completed"

    try:
        with console.status("[bold cyan]Analyzing WebSocket handshake & origin validation...[/bold cyan]", spinner="dots"):
            analysis = await WebSocketAnalyzer.analyze_endpoint(
                http_client=http_engine,
                target_url=target.normalized_url,
                auth_headers=parsed_headers,
            )

        if analysis.findings:
            db.save_findings(context.scan_id, analysis.findings)

        if not quiet:
            render_websocket_analysis_table(console, analysis)
            if analysis.findings:
                render_findings_table(console, analysis.findings)

        if output:
            out_p = Path(output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(analysis.model_dump_json(indent=2))
            console.print(f"[green][+] WebSocket analysis report saved to {out_p}[/green]")

        if any(f.severity.value in ("CRITICAL", "HIGH") for f in analysis.findings):
            exit_code = 1

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] WebSocket audit cancelled.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130
    except Exception as e:
        console.print(f"\n[bold red][ERROR] WebSocket assessment error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1
    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    return exit_code


async def execute_fuzz(
    target_url: str,
    wordlist_path: str,
    max_requests: int = 200,
    threads: int = 5,
    delay_ms: float = 20.0,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    profile: str = "safe",
    output: Optional[str] = None,
    quiet: bool = False,
    allow_private: bool = True,
) -> int:
    """Execute rate-limited, scoped directory and endpoint discovery fuzzing with a custom wordlist."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    w_path = Path(wordlist_path)
    if not w_path.exists():
        console.print(f"[bold red][ERROR][/bold red] Wordlist file not found: {wordlist_path}")
        return 1

    with open(w_path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]

    parsed_headers = parse_key_value_pairs(headers)
    parsed_cookies = parse_key_value_pairs(cookies)

    try:
        target = Target.from_url(
            target_url,
            scan_profile=profile,
            allow_private=allow_private,
        )
    except TargetValidationError as e:
        console.print(f"[bold red][ERROR][/bold red] Target validation failed: {e}")
        return 1

    scope_engine = ScopeEngine(allowed_domains=target.scope)
    rate_limiter = RateLimiter(rate=cfg.default_rate, concurrency=threads)
    context = ScanContext(target=target, config=cfg, scope=scope_engine, rate_limiter=rate_limiter)

    db = DatabaseManager(cfg.database_path)
    db.save_scan(context, status="fuzzing")

    if not quiet:
        render_target_summary(console, target, profile)
        console.print(f"[dim cyan]Wordlist:[/dim cyan] [bold white]{wordlist_path}[/bold white] ({len(words)} entries, budget: {max_requests})")
        console.print(f"[dim]Fuzz Session ID: {context.scan_id}[/dim]\n")

    http_engine = HttpEngine(
        context=context,
        default_timeout=cfg.default_timeout,
        user_agent=user_agent or cfg.default_user_agent,
        verify_tls=cfg.verify_tls,
        proxy=proxy,
    )

    fuzzer = ControlledFuzzer(
        max_requests=max_requests,
        concurrency=threads,
        delay_ms=delay_ms,
    )

    exit_code = 0
    status_label = "completed"

    try:
        with console.status(f"[bold cyan]Fuzzing target endpoints (max: {max_requests})...[/bold cyan]", spinner="dots") as status_bar:
            def on_progress(w: str, curr: int, tot: int):
                status_bar.update(f"[bold cyan]Fuzzing [{curr}/{tot}]:[/bold cyan] [dim]{w[:40]}[/dim]")

            summary = await fuzzer.fuzz_endpoints(
                http_client=http_engine,
                target_base_url=target.normalized_url,
                wordlist=words,
                progress_callback=on_progress,
            )

        if not quiet:
            render_fuzz_results_table(console, summary)

        if output:
            out_p = Path(output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(summary.model_dump_json(indent=2))
            console.print(f"[green][+] Fuzzing campaign report saved to {out_p}[/green]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Fuzzing campaign cancelled.[/bold yellow]")
        context.cancel()
        status_label = "cancelled"
        exit_code = 130
    except Exception as e:
        console.print(f"\n[bold red][ERROR] Fuzzing error: {e}[/bold red]")
        status_label = "failed"
        exit_code = 1
    finally:
        context.finish()
        await http_engine.close()
        db.update_scan_status(context.scan_id, status=status_label, stats=context.stats)

    return exit_code


async def execute_ci(
    target_url: str,
    fail_on: str = "high",
    min_confidence: int = 75,
    fail_on_regression: bool = True,
    baseline_scan_id: Optional[str] = None,
    sarif_output: Optional[str] = None,
    output: Optional[str] = None,
    threads: Optional[int] = None,
    rate: Optional[float] = None,
    timeout: Optional[float] = None,
    headers: Optional[List[str]] = None,
    cookies: Optional[List[str]] = None,
    profile: str = "ci",
    quiet: bool = False,
    allow_private: bool = True,
) -> int:
    """Execute CI/CD security quality gate assessment with SARIF export and policy threshold enforcement."""
    cfg = load_config(profile_name=profile)

    if not quiet:
        render_banner(console)

    db = DatabaseManager(cfg.database_path)

    # 1. Run standard scan
    scan_exit = await execute_scan(
        target_url=target_url,
        threads=threads,
        rate=rate,
        timeout=timeout,
        headers=headers,
        cookies=cookies,
        profile=profile,
        quiet=quiet,
        allow_private=allow_private,
    )

    if scan_exit not in (0, 1):
        return 2

    # 2. Retrieve findings from latest scan
    latest_scan = db.get_latest_scan()
    if not latest_scan:
        return 2

    current_scan_id = latest_scan["id"]
    findings_raw = db.get_findings(current_scan_id)

    findings = [
        Finding(
            id=f["id"],
            scanner=f["scanner"],
            category=f["category"],
            title=f["title"],
            severity=f["severity"],
            confidence=f["confidence"],
            status=f["status"],
            endpoint_url=f["endpoint_url"],
            parameter_name=f["parameter_name"],
            description=f.get("description") or "",
            evidence=f.get("evidence") or "",
            recommendation=f.get("recommendation") or "",
        )
        for f in findings_raw
    ]

    # 3. Export SARIF if requested
    if sarif_output:
        sarif_path = Path(sarif_output)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_json = SARIFReportGenerator.generate_sarif_json(
            findings=findings,
            target_url=target_url,
            scan_id=current_scan_id,
        )
        with open(sarif_path, "w", encoding="utf-8") as f:
            f.write(sarif_json)
        if not quiet:
            console.print(f"[green][+] SARIF 2.1.0 security report written to {sarif_path}[/green]")

    # 4. Check Policy Thresholds
    sev_hierarchy = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    threshold_val = sev_hierarchy.get(fail_on.lower(), 4)

    blocking_findings = []
    for f in findings:
        sev_str = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        sev_num = sev_hierarchy.get(sev_str, 0)
        if sev_num >= threshold_val and f.confidence >= min_confidence:
            blocking_findings.append(f)

    # 5. Check Regression if requested
    regressions_count = 0
    if fail_on_regression:
        base_id = baseline_scan_id
        if not base_id:
            past_scans = db.list_scans(limit=10)
            for s in past_scans:
                if s["id"] != current_scan_id and s.get("target_url") == target_url and s.get("status") == "completed":
                    base_id = s["id"]
                    break

        if base_id:
            findings_base_raw = db.get_findings(base_id)
            findings_base = [
                Finding(
                    id=f["id"],
                    scanner=f["scanner"],
                    category=f["category"],
                    title=f["title"],
                    severity=f["severity"],
                    confidence=f["confidence"],
                    status=f["status"],
                    endpoint_url=f["endpoint_url"],
                    parameter_name=f["parameter_name"],
                    description=f.get("description") or "",
                    evidence=f.get("evidence") or "",
                    recommendation=f.get("recommendation") or "",
                )
                for f in findings_base_raw
            ]
            reg_engine = SecurityRegressionEngine()
            reg_report = reg_engine.evaluate_regression(
                baseline_scan_id=base_id,
                current_scan_id=current_scan_id,
                baseline_findings=findings_base,
                current_findings=findings,
                target_url=target_url,
            )
            regressions_count = reg_report.summary()["regressed"]

    is_passed = len(blocking_findings) == 0 and regressions_count == 0

    if not quiet:
        render_ci_policy_summary(
            console=console,
            target=target_url,
            total_findings=len(findings),
            blocking_findings=len(blocking_findings),
            is_passed=is_passed,
            threshold=fail_on,
            regressions_count=regressions_count,
        )

    return 0 if is_passed else 1


