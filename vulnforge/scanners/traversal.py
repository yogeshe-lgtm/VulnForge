"""Path & Directory Traversal Verification Scanner."""

import re
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


class DirectoryTraversalScanner(BaseScanner):
    """Detects path traversal / arbitrary file read vulnerabilities using standard non-destructive file canaries."""

    name: str = "directory-traversal"
    description: str = "Detects directory and path traversal indicators on file parameters"
    category: str = "Directory Traversal"
    mode: ScannerMode = ScannerMode.SAFE_ACTIVE
    enabled: bool = True

    TRAVERSAL_PAYLOADS = [
        ("....//....//....//etc/passwd", re.compile(r"root:.*:0:0:", re.I), "Linux /etc/passwd root entry"),
        ("../../../../../../../../etc/passwd", re.compile(r"root:.*:0:0:", re.I), "Linux /etc/passwd root entry"),
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[fonts\]|\[extensions\]", re.I), "Windows win.ini header"),
    ]

    FILE_PARAM_KEYWORDS = {"file", "filename", "path", "doc", "document", "template", "page", "include", "view"}

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Test candidate path parameters with harmless traversal canary sequences."""
        observations: List[Observation] = []

        param_names = [
            p.name for p in endpoint.parameters
            if p.name.lower() in self.FILE_PARAM_KEYWORDS or any(kw in p.name.lower() for kw in ("file", "path", "page"))
        ]

        if not param_names and "?" in endpoint.url:
            parsed = urlparse(endpoint.url)
            param_names = list(parse_qs(parsed.query).keys())

        for param_name in param_names:
            for payload, pattern, desc in self.TRAVERSAL_PAYLOADS:
                try:
                    parsed = urlparse(endpoint.url)
                    qs = parse_qs(parsed.query)
                    qs[param_name] = [payload]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                    resp = await context.http.get(test_url)
                    if resp.is_success and resp.body:
                        match = pattern.search(resp.body)
                        if match:
                            snippet = resp.body[max(0, match.start() - 10) : min(len(resp.body), match.end() + 30)]
                            obs = self.create_observation(
                                endpoint_url=endpoint.url,
                                parameter_name=param_name,
                                description=f"Path traversal indicator: successfully retrieved {desc}",
                                observation_type=ObservationType.INFO_LEAK,
                                evidence=snippet.strip(),
                                confidence=95,
                            )
                            observations.append(obs)
                            break
                except Exception:
                    pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize Directory Traversal findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                findings.append(
                    self.create_finding(
                        title=f"Path / Directory Traversal in Parameter '{obs.parameter_name}'",
                        endpoint_url=obs.endpoint_url,
                        parameter_name=obs.parameter_name,
                        category="Directory Traversal",
                        severity=FindingSeverity.HIGH,
                        confidence=obs.confidence,
                        status=FindingStatus.CONFIRMED,
                        description=f"The application allows path traversal sequences in parameter '{obs.parameter_name}' to access arbitrary files on the underlying filesystem.",
                        evidence=obs.evidence,
                        recommendation="Validate user input against a strict whitelist of permitted files or use hardcoded indirect file reference keys.",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://portswigger.net/web-security/file-path-traversal",
                        ],
                    )
                )

        return findings
