"""Information Disclosure and Server Leak Scanner."""

import re
from typing import List

from vulnforge.models.endpoint import Endpoint
from vulnforge.scanners.base import BaseScanner, ScannerMode
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
)


class InformationDisclosureScanner(BaseScanner):
    """Detects server version banners, technology stack headers, debug traces, and sensitive patterns."""

    name: str = "information-disclosure"
    description: str = "Detects verbose server version banners, error debug traces, and sensitive metadata leaks"
    category: str = "Information Disclosure"
    mode: ScannerMode = ScannerMode.PASSIVE
    enabled: bool = True

    SERVER_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]

    DEBUG_PATTERNS = [
        (re.compile(r"Traceback \(most recent call last\):", re.I), "Python Traceback / Stack Trace"),
        (re.compile(r"Fatal error:.*on line \d+", re.I), "PHP Fatal Error Trace"),
        (re.compile(r"Exception in thread \"main\"", re.I), "Java Exception Stack Trace"),
        (re.compile(r"Microsoft OLE DB Provider for (SQL Server|ODBC Drivers)", re.I), "Database Driver Error"),
        (re.compile(r"Django Version:.*Python Version:", re.I), "Django Debug Page"),
    ]

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Inspect response headers and body content for information leaks."""
        observations: List[Observation] = []

        try:
            resp = await context.http.get(endpoint.url)

            # 1. Inspect Server Fingerprinting Headers
            for header_name in self.SERVER_LEAK_HEADERS:
                for h_key, h_val in resp.headers.items():
                    if h_key.lower() == header_name and any(char.isdigit() for char in h_val):
                        obs = self.create_observation(
                            endpoint_url=endpoint.url,
                            description=f"Server exposes detailed version information via '{h_key}': {h_val}",
                            observation_type=ObservationType.INFO_LEAK,
                            evidence=f"{h_key}: {h_val}",
                            confidence=95,
                        )
                        observations.append(obs)

            # 2. Inspect Body for Debug / Stack Trace Leaks
            if resp.body:
                for pattern, desc in self.DEBUG_PATTERNS:
                    match = pattern.search(resp.body)
                    if match:
                        snippet = resp.body[max(0, match.start() - 30) : min(len(resp.body), match.end() + 60)]
                        obs = self.create_observation(
                            endpoint_url=endpoint.url,
                            description=f"Exposed {desc} in application response body",
                            observation_type=ObservationType.ERROR_LEAK,
                            evidence=snippet.strip(),
                            confidence=90,
                        )
                        observations.append(obs)
        except Exception:
            pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize consolidated findings for information disclosure."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                if obs.observation_type == ObservationType.ERROR_LEAK:
                    findings.append(
                        self.create_finding(
                            title="Debug / Stack Trace Information Disclosure",
                            endpoint_url=obs.endpoint_url,
                            category="Information Disclosure",
                            severity=FindingSeverity.MEDIUM,
                            confidence=obs.confidence,
                            status=FindingStatus.CONFIRMED,
                            description=f"The application returned an unhandled exception or debug stack trace on '{obs.endpoint_url}'.",
                            evidence=obs.evidence,
                            recommendation="Disable verbose debugging in production environments and implement custom generic error pages.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Codes"],
                        )
                    )
                elif obs.observation_type == ObservationType.INFO_LEAK:
                    findings.append(
                        self.create_finding(
                            title="Server / Technology Version Banner Disclosure",
                            endpoint_url=obs.endpoint_url,
                            category="Information Disclosure",
                            severity=FindingSeverity.LOW,
                            confidence=obs.confidence,
                            status=FindingStatus.CONFIRMED,
                            description=f"The web server advertises detailed internal technology version banners: {obs.evidence}",
                            evidence=obs.evidence,
                            recommendation="Configure the web server or reverse proxy to strip or sanitize 'Server' and 'X-Powered-By' headers.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                        )
                    )

        return findings
