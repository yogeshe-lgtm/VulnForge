"""Insecure File Upload Form Audit Module."""

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


class FileUploadScanner(BaseScanner):
    """Detects file upload endpoints and audits for lack of type/size restriction indicators."""

    name: str = "file-upload"
    description: str = "Inspects file upload endpoints for unrestricted upload indicators"
    category: str = "File Upload"
    mode: ScannerMode = ScannerMode.ANALYSIS
    enabled: bool = True

    FILE_PARAM_NAMES = {"file", "upload", "avatar", "attachment", "document", "photo", "image", "media"}

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Inspect endpoint parameters for file upload signatures."""
        observations: List[Observation] = []

        for param in endpoint.parameters:
            if param.name.lower() in self.FILE_PARAM_NAMES or "upload" in endpoint.url.lower():
                obs = self.create_observation(
                    endpoint_url=endpoint.url,
                    parameter_name=param.name,
                    description=f"File upload interface identified on parameter '{param.name}'",
                    observation_type=ObservationType.PARAMETER_PATTERN,
                    evidence=f"Endpoint: {endpoint.method} {endpoint.url}, Parameter: {param.name}",
                    confidence=85,
                )
                observations.append(obs)

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize file upload findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                findings.append(
                    self.create_finding(
                        title=f"File Upload Endpoint Identified in '{obs.parameter_name}'",
                        endpoint_url=obs.endpoint_url,
                        parameter_name=obs.parameter_name,
                        category="File Upload",
                        severity=FindingSeverity.LOW,
                        confidence=obs.confidence,
                        status=FindingStatus.OBSERVED,
                        description=f"The application exposes a file upload parameter '{obs.parameter_name}' that should be audited for server-side MIME, extension, and content verification.",
                        evidence=obs.evidence,
                        recommendation="Validate file extensions against an allowlist, inspect magic file headers, re-encode uploaded media, and store uploads in an isolated storage bucket.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                        ],
                    )
                )

        return findings
