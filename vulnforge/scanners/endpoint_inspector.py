"""Demonstration metadata inspection scanner for discovered routes and parameters."""

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


class EndpointInspectorScanner(BaseScanner):
    """Inspects endpoint metadata, parameter patterns, and transport schemes.

    This is a safe analysis module that operates purely on discovered route metadata
    without executing additional active test payloads.
    """

    name: str = "endpoint-inspector"
    description: str = "Inspects endpoint metadata, transport schemes, and parameter signatures"
    category: str = "Architecture"
    mode: ScannerMode = ScannerMode.ANALYSIS
    enabled: bool = True

    FILE_PARAMS = {"file", "filename", "path", "doc", "document", "template", "page", "download"}
    URL_PARAMS = {"url", "uri", "redirect", "dest", "destination", "next", "return", "callback", "webhook"}
    ID_PARAMS = {"id", "user_id", "account_id", "order_id", "uid", "uuid", "doc_id"}

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Analyze an endpoint and return factual structural observations."""
        observations: List[Observation] = []

        # 1. Check scheme configuration (HTTP vs HTTPS)
        if endpoint.scheme == "http" and not context.target.is_private:
            obs = self.create_observation(
                endpoint_url=endpoint.url,
                description="Endpoint is served over unencrypted HTTP protocol",
                observation_type=ObservationType.SCHEME_CONFIGURATION,
                evidence=f"Scheme '{endpoint.scheme}' in URL '{endpoint.url}'",
                confidence=95,
            )
            observations.append(obs)

        # 2. Check query parameters presence
        if endpoint.parameters:
            obs = self.create_observation(
                endpoint_url=endpoint.url,
                description=f"Endpoint accepts {len(endpoint.parameters)} input parameters",
                observation_type=ObservationType.PARAMETER_PATTERN,
                evidence=f"Parameters: {', '.join(p.name for p in endpoint.parameters)}",
                confidence=90,
            )
            observations.append(obs)

        # 3. Analyze parameter semantic signatures
        for param in endpoint.parameters:
            param_lower = param.name.lower()

            if param_lower in self.FILE_PARAMS or any(param_lower.endswith("_" + fp) for fp in self.FILE_PARAMS):
                obs = self.create_observation(
                    endpoint_url=endpoint.url,
                    parameter_name=param.name,
                    description=f"Parameter '{param.name}' exhibits file/resource path naming convention",
                    observation_type=ObservationType.PARAMETER_PATTERN,
                    evidence=f"Parameter name '{param.name}' at location '{param.location.value}'",
                    confidence=80,
                )
                observations.append(obs)

            elif param_lower in self.URL_PARAMS or any(param_lower.endswith("_" + up) for up in self.URL_PARAMS):
                obs = self.create_observation(
                    endpoint_url=endpoint.url,
                    parameter_name=param.name,
                    description=f"Parameter '{param.name}' exhibits URL or redirection destination naming convention",
                    observation_type=ObservationType.URL_INPUT,
                    evidence=f"Parameter name '{param.name}' at location '{param.location.value}'",
                    confidence=85,
                )
                observations.append(obs)

            elif param_lower in self.ID_PARAMS or any(param_lower.endswith("_" + ip) for ip in self.ID_PARAMS):
                obs = self.create_observation(
                    endpoint_url=endpoint.url,
                    parameter_name=param.name,
                    description=f"Parameter '{param.name}' exhibits object/user identifier naming convention",
                    observation_type=ObservationType.PARAMETER_PATTERN,
                    evidence=f"Parameter name '{param.name}' at location '{param.location.value}'",
                    confidence=85,
                )
                observations.append(obs)

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize informational findings for architectural review."""
        findings: List[Finding] = []

        # Check for unencrypted HTTP endpoints on public target
        http_observations = [
            o for o in context.observations
            if o.scanner == self.name and o.observation_type == ObservationType.SCHEME_CONFIGURATION
        ]
        if http_observations and not context.target.is_private:
            findings.append(
                self.create_finding(
                    title="Unencrypted HTTP Transport In Use",
                    endpoint_url=context.target.normalized_url,
                    category="Transport Security",
                    severity=FindingSeverity.LOW,
                    confidence=95,
                    status=FindingStatus.OBSERVED,
                    description=f"Discovered {len(http_observations)} endpoints transmitting data over unencrypted HTTP.",
                    evidence=f"Sample endpoint: {http_observations[0].endpoint_url}",
                    recommendation="Enforce HTTPS via TLS/SSL and configure HTTP Strict Transport Security (HSTS).",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                )
            )

        return findings
