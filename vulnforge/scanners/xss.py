"""Reflected Cross-Site Scripting (XSS) Canary Scanner."""

import html
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


class XSSScanner(BaseScanner):
    """Detects reflected input and dangerous unencoded context reflections using safe alphanumeric canary tokens."""

    name: str = "xss"
    description: str = "Detects reflected parameters and dangerous unencoded HTML contexts using benign canary probes"
    category: str = "Cross-Site Scripting (XSS)"
    mode: ScannerMode = ScannerMode.SAFE_ACTIVE
    enabled: bool = True

    CANARY_TOKEN = "vfprobe_xss123"
    SPECIAL_CANARY = "vf\"<xss>'99"

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Inject safe canary tokens into query parameters and inspect reflection context."""
        observations: List[Observation] = []

        # Target parameters
        param_names = [p.name for p in endpoint.parameters]
        if not param_names and "?" in endpoint.url:
            parsed = urlparse(endpoint.url)
            param_names = list(parse_qs(parsed.query).keys())

        for param_name in param_names:
            try:
                parsed = urlparse(endpoint.url)
                qs = parse_qs(parsed.query)

                # 1. Test basic reflection
                qs[param_name] = [self.CANARY_TOKEN]
                new_query = urlencode(qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                resp = await context.http.get(test_url)
                if resp.is_success and resp.body and self.CANARY_TOKEN in resp.body:
                    obs1 = self.create_observation(
                        endpoint_url=endpoint.url,
                        parameter_name=param_name,
                        description=f"Input parameter '{param_name}' is reflected in the HTTP response body",
                        observation_type=ObservationType.REFLECTED_INPUT,
                        evidence=f"Canary '{self.CANARY_TOKEN}' reflected in response of {test_url}",
                        confidence=85,
                    )
                    observations.append(obs1)

                    # 2. Test special character encoding
                    qs[param_name] = [self.SPECIAL_CANARY]
                    spec_query = urlencode(qs, doseq=True)
                    spec_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, spec_query, parsed.fragment))

                    spec_resp = await context.http.get(spec_url)
                    if spec_resp.is_success and spec_resp.body:
                        if self.SPECIAL_CANARY in spec_resp.body or "<xss>" in spec_resp.body:
                            obs2 = self.create_observation(
                                endpoint_url=endpoint.url,
                                parameter_name=param_name,
                                description=f"Dangerous HTML/XML characters (< > \" ') reflected unencoded for parameter '{param_name}'",
                                observation_type=ObservationType.UNENCODED_CONTEXT,
                                evidence=f"Raw probe '{self.SPECIAL_CANARY}' returned unescaped in response",
                                confidence=95,
                            )
                            observations.append(obs2)
            except Exception:
                pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize candidate XSS findings."""
        findings: List[Finding] = []

        xss_obs = [o for o in context.observations if o.scanner == self.name]
        by_param = {}
        for o in xss_obs:
            by_param.setdefault(o.parameter_name, []).append(o)

        for param_name, obs_list in by_param.items():
            has_unencoded = any(o.observation_type == ObservationType.UNENCODED_CONTEXT for o in obs_list)
            severity = FindingSeverity.HIGH if has_unencoded else FindingSeverity.MEDIUM
            confidence = 95 if has_unencoded else 80

            findings.append(
                self.create_finding(
                    title=f"Reflected Cross-Site Scripting (XSS) in '{param_name}'",
                    endpoint_url=obs_list[0].endpoint_url,
                    parameter_name=param_name,
                    category="Cross-Site Scripting (XSS)",
                    severity=severity,
                    confidence=confidence,
                    status=FindingStatus.CONFIRMED if has_unencoded else FindingStatus.PROBABLE,
                    description=f"User-controllable input supplied to parameter '{param_name}' is reflected in the web response without adequate context-aware output encoding.",
                    evidence="; ".join(o.evidence for o in obs_list),
                    recommendation="Apply context-aware HTML entity encoding or use a secure template engine with automatic escaping enabled.",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                )
            )

        return findings
