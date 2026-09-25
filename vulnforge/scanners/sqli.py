"""SQL Injection Indicator and Error Analysis Scanner."""

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


class SQLiScanner(BaseScanner):
    """Detects database error signatures and SQL syntax anomalies using safe, non-destructive quote probes."""

    name: str = "sqli"
    description: str = "Detects database error signatures and SQL syntax anomalies via safe single-quote canary probes"
    category: str = "SQL Injection"
    mode: ScannerMode = ScannerMode.SAFE_ACTIVE
    enabled: bool = True

    SQL_ERROR_PATTERNS = [
        (re.compile(r"you have an error in your sql syntax", re.I), "MySQL Syntax Error"),
        (re.compile(r"warning:.*mysql_", re.I), "MySQL PHP Driver Warning"),
        (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL Unclosed Quotation Mark"),
        (re.compile(r"quoted string not properly terminated", re.I), "Oracle SQL Syntax Error"),
        (re.compile(r"pg_query\(\):.*Query failed:", re.I), "PostgreSQL Driver Error"),
        (re.compile(r"SQLite3::SQLException:", re.I), "SQLite Query Exception"),
        (re.compile(r"syntax error at or near", re.I), "PostgreSQL Syntax Error"),
        (re.compile(r"ODBC SQL Server Driver", re.I), "ODBC SQL Server Driver Error"),
    ]

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Inject safe quote probe and check for database error messages."""
        observations: List[Observation] = []

        param_names = [p.name for p in endpoint.parameters]
        if not param_names and "?" in endpoint.url:
            parsed = urlparse(endpoint.url)
            param_names = list(parse_qs(parsed.query).keys())

        for param_name in param_names:
            try:
                parsed = urlparse(endpoint.url)
                qs = parse_qs(parsed.query)

                # Inject single quote canary probe
                qs[param_name] = ["1'"]
                probe_query = urlencode(qs, doseq=True)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))

                resp = await context.http.get(probe_url)
                if resp.body:
                    for pattern, desc in self.SQL_ERROR_PATTERNS:
                        match = pattern.search(resp.body)
                        if match:
                            snippet = resp.body[max(0, match.start() - 20) : min(len(resp.body), match.end() + 40)]
                            obs = self.create_observation(
                                endpoint_url=endpoint.url,
                                parameter_name=param_name,
                                description=f"Database error indicator triggered by parameter '{param_name}': {desc}",
                                observation_type=ObservationType.ERROR_LEAK,
                                evidence=snippet.strip(),
                                confidence=95,
                            )
                            observations.append(obs)
                            break
            except Exception:
                pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize candidate SQLi findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                findings.append(
                    self.create_finding(
                        title=f"SQL Injection Indicator in Parameter '{obs.parameter_name}'",
                        endpoint_url=obs.endpoint_url,
                        parameter_name=obs.parameter_name,
                        category="SQL Injection",
                        severity=FindingSeverity.CRITICAL,
                        confidence=obs.confidence,
                        status=FindingStatus.CONFIRMED,
                        description=f"Supplying a single quote to parameter '{obs.parameter_name}' triggered an explicit database engine syntax error.",
                        evidence=obs.evidence,
                        recommendation="Use parameterized queries (prepared statements) with bound parameters for all database interactions.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                        ],
                    )
                )

        return findings
