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
    render_attack_surface_dashboard,
    render_attack_surface_summary,
    render_banner,
    render_endpoint_priority_table,
    render_endpoints_table,
    render_finding_detail,
    render_findings_table,
    render_forms_table,
    render_observations_table,
    render_parameter_classification_table,
    render_scan_completion_dashboard,
    render_scan_diff_table,
    render_scanner_engine_summary,
    render_scanner_registry_table,
    render_statistics,
    render_target_summary,
    render_technologies_table,
    render_top_findings,
)
from vulnforge.intelligence import AttackSurfaceBuilder
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
