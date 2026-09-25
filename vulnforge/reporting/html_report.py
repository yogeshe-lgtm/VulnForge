"""Standalone professional HTML report generator with zero external dependencies."""

from datetime import datetime, timezone
import html
from typing import Any, Dict, List, Optional

from vulnforge.scanners.result import Finding, FindingSeverity
from vulnforge.utils.redaction import redact_secrets


def generate_html_report(
    scan_data: Dict[str, Any],
    findings: List[Finding],
    endpoints: Optional[List[Any]] = None,
    technologies: Optional[List[Any]] = None,
    statistics: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a self-contained, responsive, modern dark-themed HTML report.

    Args:
        scan_data: Master scan session metadata.
        findings: Consolidated security findings.
        endpoints: Discovered endpoint inventory.
        technologies: Detected technology stack.
        statistics: HTTP request and execution statistics.

    Returns:
        Rendered HTML report string.
    """
    target = scan_data.get("target", {})
    target_url = target.get("raw_url") or scan_data.get("target_url", "Unknown Target")
    profile = scan_data.get("profile", "SAFE")
    scan_id = scan_data.get("scan_id") or scan_data.get("id", "N/A")
    created_at = scan_data.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Severity counts
    sev_counts = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 0,
        FindingSeverity.MEDIUM: 0,
        FindingSeverity.LOW: 0,
        FindingSeverity.INFO: 0,
    }
    for f in findings:
        sev = f.severity if isinstance(f.severity, FindingSeverity) else FindingSeverity(str(f.severity).upper())
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    stats = statistics or scan_data.get("statistics", {})

    # Findings Cards HTML
    findings_html_list = []
    for idx, f in enumerate(findings, 1):
        sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_class = sev_str.lower()
        status_str = f.status.value if hasattr(f.status, "value") else str(f.status)

        evidence_content = redact_secrets(f.evidence) if f.evidence else "No specific evidence recorded."
        curl_cmd = f"curl -i -s -k '{html.escape(f.endpoint_url)}'"

        refs_html = "".join(
            f'<li><a href="{html.escape(r)}" target="_blank" rel="noopener noreferrer">{html.escape(r)}</a></li>'
            for r in f.references
        ) if f.references else "<li>None specified</li>"

        card = f"""
        <div class="finding-card {sev_class}">
            <div class="finding-header">
                <div class="finding-title-group">
                    <span class="badge badge-{sev_class}">{sev_str}</span>
                    <span class="badge badge-status">{status_str}</span>
                    <h3>#{idx} {html.escape(f.title)}</h3>
                </div>
                <div class="confidence-badge">Confidence: <strong>{f.confidence}%</strong></div>
            </div>
            <div class="finding-meta">
                <div><strong>Category:</strong> {html.escape(f.category)}</div>
                <div><strong>Endpoint:</strong> <code>{html.escape(f.endpoint_url)}</code></div>
                <div><strong>Parameter:</strong> <code>{html.escape(f.parameter_name or 'N/A')}</code></div>
                <div><strong>Scanner:</strong> {html.escape(f.scanner)}</div>
            </div>
            <div class="finding-body">
                <h4>Description</h4>
                <p>{html.escape(f.description)}</p>

                <h4>Supporting Evidence</h4>
                <pre class="evidence-block"><code>{html.escape(evidence_content)}</code></pre>

                <h4>Reproduction Command</h4>
                <pre class="curl-block"><code>{html.escape(curl_cmd)}</code></pre>

                <h4>Remediation Guidance</h4>
                <p class="remediation-text">{html.escape(f.recommendation)}</p>

                <h4>References</h4>
                <ul class="references-list">{refs_html}</ul>
            </div>
        </div>
        """
        findings_html_list.append(card)

    findings_section = "\n".join(findings_html_list) if findings_html_list else "<p class='no-findings'>No security findings or vulnerabilities identified.</p>"

    # Technology Stack HTML
    tech_list = technologies if isinstance(technologies, list) else scan_data.get("technologies", [])
    tech_rows = []
    for t in (tech_list or []):
        if isinstance(t, dict):
            name = t.get("name", "")
            cat = t.get("category", "")
            ver = str(t.get("version") or "-")
            conf = t.get("confidence", 0)
        else:
            name = str(t)
            cat = "General"
            ver = "-"
            conf = 100
        tech_rows.append(
            f'<tr><td><strong>{html.escape(name)}</strong></td><td>{html.escape(cat)}</td><td>{html.escape(ver)}</td><td><span class="badge badge-info">{conf}%</span></td></tr>'
        )
    tech_html = "".join(tech_rows) if tech_rows else "<tr><td colspan='4'>No third-party technologies detected.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnForge Security Assessment Report — {html.escape(target_url)}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-hover: #21262d;
            --border: #30363d;
            --text-main: #c9d1d9;
            --text-heading: #f0f6fc;
            --text-dim: #8b949e;
            --cyan: #00bcd4;
            --blue: #58a6ff;
            --green: #3fb950;
            --yellow: #d29922;
            --orange: #f0883e;
            --red: #f85149;
            --critical: #ff2a5f;
            --high: #f85149;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: var(--bg); color: var(--text-main); line-height: 1.6; padding: 30px 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; }}
        .brand {{ font-size: 24px; font-weight: bold; color: var(--cyan); letter-spacing: 1px; }}
        .brand span {{ color: var(--text-heading); }}
        .report-meta {{ font-size: 13px; color: var(--text-dim); text-align: right; }}
        h2 {{ color: var(--text-heading); font-size: 20px; margin-bottom: 16px; border-left: 4px solid var(--cyan); padding-left: 10px; }}
        .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 25px; }}
        
        /* Summary Grid */
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 25px; }}
        .summary-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; text-align: center; }}
        .summary-card .number {{ font-size: 28px; font-weight: bold; color: var(--text-heading); margin-bottom: 4px; }}
        .summary-card .label {{ font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }}
        
        /* Vulnerability Metrics Bar */
        .sev-bar-container {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
        .sev-pill {{ flex: 1; min-width: 130px; padding: 12px; border-radius: 6px; text-align: center; font-weight: bold; border: 1px solid transparent; }}
        .sev-pill.critical {{ background: rgba(255, 42, 95, 0.15); color: var(--critical); border-color: var(--critical); }}
        .sev-pill.high {{ background: rgba(248, 81, 73, 0.15); color: var(--high); border-color: var(--high); }}
        .sev-pill.medium {{ background: rgba(210, 153, 34, 0.15); color: var(--medium); border-color: var(--medium); }}
        .sev-pill.low {{ background: rgba(63, 185, 80, 0.15); color: var(--low); border-color: var(--low); }}
        .sev-pill.info {{ background: rgba(88, 166, 255, 0.15); color: var(--info); border-color: var(--info); }}
        
        /* Badges */
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #fff; }}
        .badge-info {{ background: var(--info); color: #000; }}
        .badge-status {{ background: #21262d; color: var(--text-dim); border: 1px solid var(--border); }}
        
        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #21262d; color: var(--text-heading); font-weight: 600; }}
        tr:hover {{ background: var(--surface-hover); }}
        
        /* Finding Cards */
        .finding-card {{ background: var(--bg); border: 1px solid var(--border); border-left: 5px solid var(--border); border-radius: 6px; padding: 20px; margin-bottom: 20px; }}
        .finding-card.critical {{ border-left-color: var(--critical); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--medium); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-card.info {{ border-left-color: var(--info); }}
        
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 10px; }}
        .finding-title-group {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .finding-title-group h3 {{ font-size: 17px; color: var(--text-heading); }}
        .confidence-badge {{ font-size: 13px; color: var(--cyan); background: rgba(0, 188, 212, 0.1); padding: 4px 10px; border-radius: 12px; border: 1px solid rgba(0, 188, 212, 0.3); }}
        
        .finding-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; font-size: 13px; background: var(--surface); padding: 10px 14px; border-radius: 4px; margin-bottom: 15px; border: 1px solid var(--border); }}
        .finding-meta code {{ background: #0d1117; padding: 2px 6px; border-radius: 3px; color: var(--cyan); font-family: monospace; }}
        
        .finding-body h4 {{ font-size: 13px; text-transform: uppercase; color: var(--text-dim); margin: 12px 0 6px 0; letter-spacing: 0.5px; }}
        .finding-body p {{ font-size: 14px; margin-bottom: 8px; }}
        
        pre {{ background: #090d13; border: 1px solid var(--border); padding: 12px; border-radius: 4px; overflow-x: auto; font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 13px; color: #79c0ff; margin-bottom: 10px; }}
        .remediation-text {{ background: rgba(63, 185, 80, 0.08); border-left: 3px solid var(--green); padding: 10px 14px; border-radius: 0 4px 4px 0; color: #7ee787; }}
        .references-list {{ margin-left: 20px; font-size: 13px; }}
        .references-list a {{ color: var(--blue); text-decoration: none; word-break: break-all; }}
        .references-list a:hover {{ text-decoration: underline; }}
        
        footer {{ text-align: center; font-size: 12px; color: var(--text-dim); margin-top: 40px; border-top: 1px solid var(--border); padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand">VULN<span>FORGE</span></div>
                <div style="font-size: 13px; color: var(--text-dim);">Automated Web Security Assessment Engine</div>
            </div>
            <div class="report-meta">
                <div>Scan ID: <code>{html.escape(scan_id)}</code></div>
                <div>Generated: {html.escape(created_at)}</div>
                <div>Profile: <strong>{html.escape(profile.upper())}</strong></div>
            </div>
        </header>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="sev-bar-container">
                <div class="sev-pill critical">CRITICAL: {sev_counts[FindingSeverity.CRITICAL]}</div>
                <div class="sev-pill high">HIGH: {sev_counts[FindingSeverity.HIGH]}</div>
                <div class="sev-pill medium">MEDIUM: {sev_counts[FindingSeverity.MEDIUM]}</div>
                <div class="sev-pill low">LOW: {sev_counts[FindingSeverity.LOW]}</div>
                <div class="sev-pill info">INFO: {sev_counts[FindingSeverity.INFO]}</div>
            </div>
            <p style="font-size: 14px; color: var(--text-dim);">
                Target <strong>{html.escape(target_url)}</strong> was assessed using VulnForge's multi-tier reconnaissance, discovery, and modular scanner framework. A total of <strong>{len(findings)}</strong> correlated security findings were synthesized.
            </p>
        </div>

        <!-- Scan Statistics & Attack Surface -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{stats.get("requests_sent", 0)}</div>
                <div class="label">Requests Dispatched</div>
            </div>
            <div class="summary-card">
                <div class="number">{len(endpoints) if endpoints else stats.get("endpoints_count", 0)}</div>
                <div class="label">Discovered Endpoints</div>
            </div>
            <div class="summary-card">
                <div class="number">{len(tech_list)}</div>
                <div class="label">Identified Technologies</div>
            </div>
            <div class="summary-card">
                <div class="number">{stats.get("duration_seconds", 0.0):.1f}s</div>
                <div class="label">Execution Duration</div>
            </div>
        </div>

        <!-- Identified Technologies -->
        <div class="section">
            <h2>Technology Stack Fingerprints</h2>
            <table>
                <thead>
                    <tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th></tr>
                </thead>
                <tbody>
                    {tech_html}
                </tbody>
            </table>
        </div>

        <!-- Detailed Findings -->
        <div class="section">
            <h2>Correlated Security Findings ({len(findings)})</h2>
            {findings_section}
        </div>

        <footer>
            VulnForge Security Assessment Report &bull; Authorized Security Research Only &bull; Secret Redaction Enabled
        </footer>
    </div>
</body>
</html>
"""
