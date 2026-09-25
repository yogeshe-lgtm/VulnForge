"""Machine-readable JSON report generator."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from vulnforge import __version__
from vulnforge.scanners.result import Finding
from vulnforge.utils.redaction import redact_dict_secrets


def generate_json_report(
    scan_data: Dict[str, Any],
    findings: List[Finding],
    endpoints: Optional[List[Any]] = None,
    technologies: Optional[List[Any]] = None,
    statistics: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate structured JSON report string with redacted secrets.

    Args:
        scan_data: Scan session metadata and target dict.
        findings: List of Finding models.
        endpoints: Discovered endpoint inventory.
        technologies: Detected technology stack.
        statistics: Scan execution statistics.

    Returns:
        JSON string representation formatted with 2 spaces indentation.
    """
    target = scan_data.get("target", {})
    stats = statistics or scan_data.get("statistics", {})

    report = {
        "metadata": {
            "tool": "VulnForge",
            "version": __version__,
            "scan_id": scan_data.get("scan_id") or scan_data.get("id", ""),
            "profile": scan_data.get("profile", "safe"),
            "status": scan_data.get("status", "completed"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "target": target if isinstance(target, dict) else target.model_dump() if hasattr(target, "model_dump") else str(target),
        "statistics": stats,
        "technologies": technologies or [],
        "attack_surface": {
            "endpoints_count": len(endpoints) if endpoints else 0,
            "endpoints": [
                ep.model_dump(mode="json") if hasattr(ep, "model_dump")
                else ep if isinstance(ep, dict)
                else str(ep)
                for ep in (endpoints or [])
            ],
        },
        "findings_summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if str(f.severity).upper() in ("CRITICAL", "FINDINGSEVERITY.CRITICAL")),
            "high": sum(1 for f in findings if str(f.severity).upper() in ("HIGH", "FINDINGSEVERITY.HIGH")),
            "medium": sum(1 for f in findings if str(f.severity).upper() in ("MEDIUM", "FINDINGSEVERITY.MEDIUM")),
            "low": sum(1 for f in findings if str(f.severity).upper() in ("LOW", "FINDINGSEVERITY.LOW")),
            "info": sum(1 for f in findings if str(f.severity).upper() in ("INFO", "FINDINGSEVERITY.INFO")),
        },
        "findings": [
            f.model_dump(mode="json") if hasattr(f, "model_dump") else f
            for f in findings
        ],
    }

    sanitized_report = redact_dict_secrets(report)
    return json.dumps(sanitized_report, indent=2, default=str)
