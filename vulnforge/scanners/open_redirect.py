"""Open Redirection Scanner using safe canary validation."""

from typing import List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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


class OpenRedirectScanner(BaseScanner):
    """Detects unvalidated external redirection vulnerabilities on URL parameters."""

    name: str = "open-redirect"
    description: str = "Detects unvalidated external redirection using safe test destinations"
    category: str = "Open Redirect"
    mode: ScannerMode = ScannerMode.SAFE_ACTIVE
    enabled: bool = True

    SAFE_CANARY = "https://example.com"
    REDIRECT_PARAMS = {"redirect", "url", "next", "return", "dest", "destination", "target", "goto", "out", "r"}

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Test URL parameters for arbitrary external redirection."""
        observations: List[Observation] = []

        # Find candidate parameters
        candidate_params = [
            p.name for p in endpoint.parameters
            if p.name.lower() in self.REDIRECT_PARAMS or any(rp in p.name.lower() for rp in ("url", "redirect", "dest", "next"))
        ]

        if not candidate_params and "?" in endpoint.url:
            parsed = urlparse(endpoint.url)
            qs = parse_qs(parsed.query)
            candidate_params = list(qs.keys())

        for param_name in candidate_params:
            try:
                parsed = urlparse(endpoint.url)
                qs = parse_qs(parsed.query)
                qs[param_name] = [self.SAFE_CANARY]
                new_query = urlencode(qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                resp = await context.http.get(test_url, follow_redirects=False)
                location = resp.headers.get("location") or resp.headers.get("Location")

                if resp.status_code in (301, 302, 303, 307, 308) and location:
                    if location.startswith("https://example.com") or location.startswith("//example.com"):
                        obs = self.create_observation(
                            endpoint_url=endpoint.url,
                            parameter_name=param_name,
                            description=f"Parameter '{param_name}' redirects directly to untrusted external destination",
                            observation_type=ObservationType.HTTP_STATUS_CHANGE,
                            evidence=f"GET {test_url} -> HTTP {resp.status_code} Location: {location}",
                            confidence=95,
                        )
                        observations.append(obs)
            except Exception:
                pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize Open Redirect findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                findings.append(
                    self.create_finding(
                        title="Unvalidated Open URL Redirection",
                        endpoint_url=obs.endpoint_url,
                        parameter_name=obs.parameter_name,
                        category="Open Redirect",
                        severity=FindingSeverity.MEDIUM,
                        confidence=obs.confidence,
                        status=FindingStatus.CONFIRMED,
                        description=f"The endpoint accepts an unvalidated external destination parameter '{obs.parameter_name}' and redirects the user via HTTP 3xx Location header.",
                        evidence=obs.evidence,
                        recommendation="Validate destination URLs against an explicit allowlist of relative paths or trusted domains.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/open-redirection",
                        ],
                    )
                )

        return findings
