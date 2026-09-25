"""SARIF 2.1.0 (Static Analysis Results Interchange Format) Report Generator."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vulnforge import __version__
from vulnforge.scanners.result import Finding, FindingSeverity


class SARIFReportGenerator:
    """Generates OASIS SARIF 2.1.0 compliant security reports for CI/CD and GitHub Code Scanning."""

    @staticmethod
    def _map_severity_to_sarif_level(severity: FindingSeverity) -> str:
        """Map VulnForge FindingSeverity to SARIF result level."""
        sev_name = severity.name if hasattr(severity, "name") else str(severity).upper()
        if sev_name in ("CRITICAL", "HIGH"):
            return "error"
        elif sev_name == "MEDIUM":
            return "warning"
        elif sev_name in ("LOW", "INFO"):
            return "note"
        return "none"

    @classmethod
    def generate_sarif(
        cls,
        findings: List[Finding],
        target_url: str = "https://example.com",
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Produce a valid SARIF 2.1.0 log dictionary."""
        # Collect distinct rules
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for f in findings:
            rule_id = f"VF-{f.scanner.upper()}-{abs(hash(f.title)) % 10000:04d}"

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f.title.replace(" ", ""),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description or f.title},
                    "defaultConfiguration": {
                        "level": cls._map_severity_to_sarif_level(f.severity),
                    },
                    "help": {
                        "text": f"Remediation: {f.recommendation}\n\nReferences:\n" + "\n".join(f"- {r}" for r in f.references),
                        "markdown": f"### Remediation\n{f.recommendation}\n\n### References\n" + "\n".join(f"- [{r}]({r})" for r in f.references),
                    },
                    "properties": {
                        "category": f.category,
                        "tags": ["security", "web", f.category.lower().replace(" ", "-")],
                    },
                }

            result_item: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": cls._map_severity_to_sarif_level(f.severity),
                "message": {
                    "text": f"{f.title}: {f.description}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.endpoint_url,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        },
                    }
                ],
                "properties": {
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "confidence": f.confidence,
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "parameter": f.parameter_name or "",
                    "evidence": f.evidence or "",
                    "fingerprint": f.fingerprint,
                },
            }
            sarif_results.append(result_item)

        sarif_log: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VulnForge",
                            "version": __version__,
                            "informationUri": "https://github.com/yogeshe-lgtm/VulnForge",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

        return sarif_log

    @classmethod
    def generate_sarif_json(
        cls,
        findings: List[Finding],
        target_url: str = "https://example.com",
        scan_id: Optional[str] = None,
        indent: int = 2,
    ) -> str:
        """Produce formatted SARIF 2.1.0 JSON string."""
        data = cls.generate_sarif(findings, target_url=target_url, scan_id=scan_id)
        return json.dumps(data, indent=indent)
