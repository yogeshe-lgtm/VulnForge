"""Passive Security Headers Assessment Module."""

from typing import List, Set

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


class SecurityHeadersScanner(BaseScanner):
    """Audits HTTP response headers for missing or misconfigured security controls."""

    name: str = "security-headers"
    description: str = "Audits HTTP response headers for missing or weak security controls (CSP, HSTS, X-Frame-Options, etc.)"
    category: str = "Security Headers"
    mode: ScannerMode = ScannerMode.PASSIVE
    enabled: bool = True

    CRITICAL_HEADERS = {
        "content-security-policy": ("Content-Security-Policy", FindingSeverity.MEDIUM, "Missing Content-Security-Policy (CSP) allows execution of untrusted scripts and increases XSS risk."),
        "strict-transport-security": ("Strict-Transport-Security", FindingSeverity.LOW, "Missing HSTS allows downgrade attacks and insecure transport exposure."),
        "x-content-type-options": ("X-Content-Type-Options", FindingSeverity.LOW, "Missing X-Content-Type-Options allows MIME-sniffing attacks."),
        "x-frame-options": ("X-Frame-Options", FindingSeverity.LOW, "Missing X-Frame-Options or frame-ancestors directive allows clickjacking attacks."),
        "referrer-policy": ("Referrer-Policy", FindingSeverity.INFO, "Missing Referrer-Policy may leak sensitive URL parameters to third parties."),
    }

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Perform passive header audit on the endpoint."""
        observations: List[Observation] = []

        try:
            resp = await context.http.get(endpoint.url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header_key, (header_name, sev, desc) in self.CRITICAL_HEADERS.items():
                if header_key not in headers_lower:
                    obs = self.create_observation(
                        endpoint_url=endpoint.url,
                        description=f"Missing security header: {header_name}",
                        observation_type=ObservationType.HEADER_MISSING,
                        evidence=f"Header '{header_name}' was not returned by server.",
                        confidence=100,
                    )
                    observations.append(obs)
                else:
                    # Check for weak header values
                    val = headers_lower[header_key]
                    if header_key == "x-frame-options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                        obs = self.create_observation(
                            endpoint_url=endpoint.url,
                            description=f"Weak X-Frame-Options header configuration: '{val}'",
                            observation_type=ObservationType.SECURITY_HEADER,
                            evidence=f"X-Frame-Options: {val}",
                            confidence=90,
                        )
                        observations.append(obs)
        except Exception:
            pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize consolidated findings for missing security headers."""
        findings: List[Finding] = []
        missing_by_header: Set[str] = set()

        for obs in context.observations:
            if obs.scanner == self.name and obs.observation_type == ObservationType.HEADER_MISSING:
                for header_key, (header_name, sev, desc) in self.CRITICAL_HEADERS.items():
                    if header_name in obs.description:
                        missing_by_header.add(header_key)

        for header_key in missing_by_header:
            header_name, sev, desc = self.CRITICAL_HEADERS[header_key]
            findings.append(
                self.create_finding(
                    title=f"Missing Security Header: {header_name}",
                    endpoint_url=context.target.normalized_url,
                    category="Security Headers",
                    severity=sev,
                    confidence=100,
                    status=FindingStatus.CONFIRMED,
                    description=desc,
                    evidence=f"Target web server at '{context.target.normalized_url}' does not emit the '{header_name}' HTTP response header.",
                    recommendation=f"Configure the web server or application reverse proxy to send '{header_name}'.",
                    references=[
                        f"https://owasp.org/www-project-secure-headers/",
                        f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                    ],
                )
            )

        return findings
