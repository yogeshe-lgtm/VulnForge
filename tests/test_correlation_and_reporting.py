"""Unit tests for Phase 4 Finding Correlation, Confidence Scoring, and Reporting."""

import json
import pytest
from datetime import datetime, timezone
from typing import List

from vulnforge.core.config import VulnForgeConfig
from vulnforge.core.context import ScanContext
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.correlation.confidence import (
    ConfidenceEngine,
    ConfidenceLevel,
    ConfidenceReport,
    ConfidenceSignal,
)
from vulnforge.correlation.deduplicator import FindingDeduplicator
from vulnforge.correlation.engine import CorrelationEngine
from vulnforge.correlation.severity import (
    AuthRequirement,
    DataExposureLevel,
    SeverityEngine,
)
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.response import HttpResponse
from vulnforge.models.target import Target
from vulnforge.reporting.html_report import generate_html_report
from vulnforge.reporting.json_report import generate_json_report
from vulnforge.reporting.markdown_report import generate_markdown_report
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
    compare_responses,
)
from vulnforge.storage.database import DatabaseManager
from vulnforge.utils.redaction import redact_dict_secrets, redact_secrets


def create_mock_scan_context(url: str = "https://example.local") -> ScanContext:
    """Helper to generate a mock ScanContext."""
    target = Target.from_url(url, allow_private=True)
    config = VulnForgeConfig()
    scope = ScopeEngine(allowed_domains=target.scope)
    rate_limiter = RateLimiter(rate=10.0, concurrency=2)
    return ScanContext(
        target=target,
        config=config,
        scope=scope,
        rate_limiter=rate_limiter,
    )


class TestConfidenceEngine:
    """Tests for explainable confidence calculation and score bands."""

    def test_confidence_bands(self):
        """Verify confidence level classification bands."""
        assert ConfidenceLevel.from_score(95) == ConfidenceLevel.HIGH
        assert ConfidenceLevel.from_score(90) == ConfidenceLevel.HIGH
        assert ConfidenceLevel.from_score(85) == ConfidenceLevel.PROBABLE
        assert ConfidenceLevel.from_score(70) == ConfidenceLevel.PROBABLE
        assert ConfidenceLevel.from_score(60) == ConfidenceLevel.POTENTIAL
        assert ConfidenceLevel.from_score(40) == ConfidenceLevel.POTENTIAL
        assert ConfidenceLevel.from_score(30) == ConfidenceLevel.INSUFFICIENT
        assert ConfidenceLevel.from_score(0) == ConfidenceLevel.INSUFFICIENT

    def test_explainable_signals(self):
        """Verify explainable confidence evaluation from observations and deltas."""
        obs1 = Observation(
            scanner="xss-scanner",
            endpoint_url="https://example.local/search",
            parameter_name="q",
            observation_type=ObservationType.REFLECTION,
            description="Input reflected in response body",
        )
        obs2 = Observation(
            scanner="error-scanner",
            endpoint_url="https://example.local/search",
            parameter_name="q",
            observation_type=ObservationType.ERROR_PATTERN,
            description="Syntax error disclosed",
        )

        resp1 = HttpResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="Search results for normal query",
            url="https://example.local/search",
            request_url="https://example.local/search",
            elapsed=0.1,
            request_method="GET",
        )
        resp2 = HttpResponse(
            status_code=500,
            headers={"Content-Type": "text/html"},
            body="Internal error: unescaped payload",
            url="https://example.local/search",
            request_url="https://example.local/search",
            elapsed=0.2,
            request_method="GET",
        )
        diff = compare_responses(resp1, resp2)

        report = ConfidenceEngine.evaluate(
            base_score=50,
            observations=[obs1, obs2],
            response_diff=diff,
        )

        assert report.score >= 80
        assert len(report.signals) >= 3
        # Ensure signals have explainable display text
        explanations = report.signal_explanations
        assert any("Input reflected" in e for e in explanations)
        assert any("error disclosed" in e.lower() or "error" in e.lower() for e in explanations)
        assert any("HTTP status changed" in e for e in explanations)


class TestSeverityEngine:
    """Tests for contextual severity calculations."""

    def test_severity_critical_for_rce_sqli(self):
        """Verify critical severity for RCE/SQLi categories."""
        sev = SeverityEngine.calculate_severity(
            category="SQL Injection",
            endpoint_url="https://example.local/api/query",
            confidence_score=95,
        )
        assert sev == FindingSeverity.CRITICAL

    def test_severity_path_and_exposure_modulation(self):
        """Verify severity increases on sensitive paths and data exposure."""
        # Baseline info disclosure on public static
        sev_normal = SeverityEngine.calculate_severity(
            category="Information Disclosure",
            endpoint_url="https://example.local/public/about",
            confidence_score=70,
        )

        # Info disclosure on /admin with credential exposure
        sev_sensitive = SeverityEngine.calculate_severity(
            category="Information Disclosure",
            endpoint_url="https://example.local/admin/config",
            confidence_score=90,
            data_exposure=DataExposureLevel.CREDENTIALS,
        )

        order = {FindingSeverity.CRITICAL: 5, FindingSeverity.HIGH: 4, FindingSeverity.MEDIUM: 3, FindingSeverity.LOW: 2, FindingSeverity.INFO: 1}
        assert order[sev_sensitive] > order[sev_normal]

    def test_severity_dampened_by_low_confidence(self):
        """Verify low confidence dampens high severity."""
        sev = SeverityEngine.calculate_severity(
            category="Cross-Site Scripting",
            endpoint_url="https://example.local/search",
            confidence_score=20,  # Insufficient confidence
        )
        assert sev in (FindingSeverity.LOW, FindingSeverity.INFO, FindingSeverity.MEDIUM)


class TestFindingDeduplication:
    """Tests for merging duplicate findings and consolidating evidence."""

    def test_deduplicate_and_merge_findings(self):
        """Verify duplicate findings on the same endpoint/param/category are merged."""
        f1 = Finding(
            scanner="scanner-a",
            category="XSS",
            title="Reflected XSS",
            severity=FindingSeverity.MEDIUM,
            confidence=75,
            endpoint_url="https://example.local/search",
            parameter_name="q",
            description="Payload reflected in body",
            evidence="Evidence from scanner A with token=secret123",
            references=["https://owasp.org/xss"],
        )
        f2 = Finding(
            scanner="scanner-b",
            category="XSS",
            title="Reflected XSS",
            severity=FindingSeverity.HIGH,  # Higher severity
            confidence=90,                  # Higher confidence
            endpoint_url="https://example.local/search",
            parameter_name="q",
            description="Payload reflected without encoding",
            evidence="Evidence from scanner B",
            references=["https://owasp.org/xss", "https://cwe.mitre.org/79"],
        )

        merged = FindingDeduplicator.merge([f1, f2])
        assert len(merged) == 1
        result = merged[0]
        assert result.severity == FindingSeverity.HIGH
        assert result.confidence == 90
        assert "scanner-a" in result.scanner and "scanner-b" in result.scanner
        assert len(result.references) == 2
        # Secret should be redacted
        assert "secret123" not in result.evidence


class TestCorrelationEngine:
    """Tests for multi-signal observation correlation."""

    def test_correlation_engine_synthesizes_findings(self):
        """Verify observations are correlated into findings."""
        engine = CorrelationEngine()
        obs1 = Observation(
            scanner="reflection-inspector",
            endpoint_url="https://example.local/profile",
            parameter_name="name",
            observation_type=ObservationType.REFLECTION,
            description="Input reflected in response",
            evidence="name=Alice",
        )
        obs2 = Observation(
            scanner="pattern-inspector",
            endpoint_url="https://example.local/profile",
            parameter_name="name",
            observation_type=ObservationType.PARAMETER_PATTERN,
            description="Parameter accepts arbitrary input",
        )

        findings = engine.correlate(observations=[obs1, obs2])
        assert len(findings) == 1
        f = findings[0]
        assert f.endpoint_url == "https://example.local/profile"
        assert f.parameter_name == "name"
        assert f.category == "Input Validation"


class TestSecretRedaction:
    """Tests for sensitive secret and token redaction."""

    def test_redact_secrets_string(self):
        """Verify tokens, authorization headers, passwords, and AWS keys are redacted."""
        text = "Request sent with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis and api_key=secretKey987654321"
        sanitized = redact_secrets(text)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
        assert "secretKey987654321" not in sanitized
        assert "[REDACTED" in sanitized

    def test_redact_dict_secrets(self):
        """Verify dictionary data structures have sensitive keys masked."""
        data = {
            "endpoint": "https://example.local/login",
            "password": "SuperSecretPassword123!",
            "headers": {
                "Authorization": "Bearer tokenXYZ",
                "Content-Type": "application/json",
            },
        }
        sanitized = redact_dict_secrets(data)
        assert sanitized["password"] == "[REDACTED]"
        assert "tokenXYZ" not in sanitized["headers"]["Authorization"]


class TestReportGeneration:
    """Tests for HTML, JSON, and Markdown report generation."""

    def setup_method(self):
        self.scan_meta = {
            "scan_id": "test-scan-1234",
            "target": {"raw_url": "https://example.local", "hostname": "example.local"},
            "profile": "standard",
            "statistics": {
                "requests_sent": 150,
                "requests_successful": 148,
                "duration_seconds": 12.5,
            },
        }
        self.finding = Finding(
            scanner="test-scanner",
            category="Security Headers",
            title="Missing Content-Security-Policy",
            severity=FindingSeverity.LOW,
            confidence=100,
            status=FindingStatus.CONFIRMED,
            endpoint_url="https://example.local/",
            description="CSP header is missing.",
            evidence="Headers: Server=nginx Authorization: Bearer secretToken999",
            recommendation="Configure a robust Content-Security-Policy header.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
        )

    def test_generate_json_report(self):
        """Verify JSON report structure and secret sanitization."""
        json_str = generate_json_report(
            scan_data=self.scan_meta,
            findings=[self.finding],
            endpoints=[Endpoint.from_url("https://example.local/", method="GET")],
        )
        data = json.loads(json_str)
        assert data["metadata"]["scan_id"] == "test-scan-1234"
        assert data["findings_summary"]["total"] == 1
        assert data["findings_summary"]["low"] == 1
        assert "secretToken999" not in json_str

    def test_generate_html_report(self):
        """Verify HTML report contains summary, finding details, and zero external scripts."""
        html_str = generate_html_report(
            scan_data=self.scan_meta,
            findings=[self.finding],
            endpoints=[Endpoint.from_url("https://example.local/", method="GET")],
        )
        assert "<!DOCTYPE html>" in html_str
        assert "Missing Content-Security-Policy" in html_str
        assert "100%" in html_str
        assert "secretToken999" not in html_str
        # Ensure self-contained (no external http script tags)
        assert "<script src=\"http" not in html_str

    def test_generate_markdown_report(self):
        """Verify Markdown report generation."""
        md_str = generate_markdown_report(
            scan_data=self.scan_meta,
            findings=[self.finding],
            endpoints=[Endpoint.from_url("https://example.local/", method="GET")],
        )
        assert "# VulnForge Security Assessment Report" in md_str
        assert "| **LOW** | `1` |" in md_str
        assert "curl -i -s -k" in md_str
        assert "secretToken999" not in md_str


class TestHistoryAndDiff:
    """Tests for database history aggregation and scan diffing."""

    def test_database_history_with_finding_counts(self):
        """Verify list_scans aggregates total findings and severity counts."""
        db = DatabaseManager(":memory:")
        scan_ctx = create_mock_scan_context("https://example.local")
        db.save_scan(scan_ctx, status="completed")

        f1 = Finding(
            scanner="test",
            category="Injection",
            title="SQLi",
            severity=FindingSeverity.HIGH,
            endpoint_url="https://example.local/user",
            description="SQLi detected",
        )
        f2 = Finding(
            scanner="test",
            category="Header",
            title="CSP",
            severity=FindingSeverity.LOW,
            endpoint_url="https://example.local/",
            description="CSP missing",
        )
        db.save_findings(scan_ctx.scan_id, [f1, f2])

        scans = db.list_scans()
        assert len(scans) == 1
        scan_row = scans[0]
        assert scan_row["findings_count"] == 2
        assert scan_row["high_count"] == 1
        assert scan_row["low_count"] == 1

    def test_scan_diff_computation(self):
        """Verify diff categorizes new, resolved, and unchanged findings."""
        db = DatabaseManager(":memory:")
        ctx1 = create_mock_scan_context("https://example.local")
        ctx2 = create_mock_scan_context("https://example.local")
        db.save_scan(ctx1, status="completed")
        db.save_scan(ctx2, status="completed")

        # Scan 1 findings: Issue A, Issue B
        f_a1 = Finding(scanner="t", category="XSS", title="XSS in search", severity=FindingSeverity.HIGH, endpoint_url="https://example.local/search", parameter_name="q", description="desc")
        f_b = Finding(scanner="t", category="Headers", title="Missing HSTS", severity=FindingSeverity.LOW, endpoint_url="https://example.local/", description="desc")
        db.save_findings(ctx1.scan_id, [f_a1, f_b])

        # Scan 2 findings: Issue A (unchanged), Issue C (new) -> Issue B resolved
        f_a2 = Finding(scanner="t", category="XSS", title="XSS in search", severity=FindingSeverity.HIGH, endpoint_url="https://example.local/search", parameter_name="q", description="desc")
        f_c = Finding(scanner="t", category="Auth", title="BOLA in profile", severity=FindingSeverity.HIGH, endpoint_url="https://example.local/api/profile", parameter_name="id", description="desc")
        db.save_findings(ctx2.scan_id, [f_a2, f_c])


        findings_1 = db.get_findings(ctx1.scan_id)
        findings_2 = db.get_findings(ctx2.scan_id)

        def f_key(f):
            return f"{f.get('endpoint_url')}::{f.get('parameter_name') or ''}::{f.get('title')}"

        f1_map = {f_key(f): f for f in findings_1}
        f2_map = {f_key(f): f for f in findings_2}

        new_findings = [f for k, f in f2_map.items() if k not in f1_map]
        resolved_findings = [f for k, f in f1_map.items() if k not in f2_map]
        unchanged_findings = [f for k, f in f2_map.items() if k in f1_map]

        assert len(new_findings) == 1
        assert new_findings[0]["title"] == "BOLA in profile"
        assert len(resolved_findings) == 1
        assert resolved_findings[0]["title"] == "Missing HSTS"
        assert len(unchanged_findings) == 1
        assert unchanged_findings[0]["title"] == "XSS in search"
