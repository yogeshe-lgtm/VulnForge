"""Unit and integration tests for Finding Lifecycle, Evidence Engine, and Security Regression (Phases 5, 6, 7)."""

from datetime import datetime, timezone
import pytest
from typer.testing import CliRunner

from vulnforge.cli.main import app
from vulnforge.correlation.lifecycle import FindingLifecycleManager
from vulnforge.correlation.regression import (
    RegressionStatus,
    SecurityRegressionEngine,
    SecurityRegressionReport,
)
from vulnforge.models.evidence import (
    EvidenceCollection,
    EvidenceItem,
    EvidenceType,
)
from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus


@pytest.fixture
def sample_findings_base() -> list[Finding]:
    """Create a baseline set of findings."""
    f1 = Finding(
        id="VF-001",
        scanner="xss",
        category="Cross-Site Scripting",
        title="Reflected XSS in search",
        severity=FindingSeverity.HIGH,
        confidence=85,
        status=FindingStatus.CONFIRMED,
        endpoint_url="https://example.com/search",
        parameter_name="q",
        description="Reflected XSS in search parameter",
    )
    f2 = Finding(
        id="VF-002",
        scanner="security_headers",
        category="Configuration",
        title="Missing CSP Header",
        severity=FindingSeverity.LOW,
        confidence=95,
        status=FindingStatus.CONFIRMED,
        endpoint_url="https://example.com/",
        description="Content-Security-Policy header is missing",
    )
    f3 = Finding(
        id="VF-003",
        scanner="cors",
        category="CORS",
        title="Insecure CORS Wildcard",
        severity=FindingSeverity.MEDIUM,
        confidence=80,
        status=FindingStatus.RESOLVED,
        endpoint_url="https://example.com/api/data",
        description="Access-Control-Allow-Origin: *",
    )
    return [f1, f2, f3]


def test_evidence_collection_and_redaction():
    """Verify evidence model automatically redacts passwords, tokens, and authorization headers."""
    collection = EvidenceCollection()
    item = collection.add(
        evidence_type=EvidenceType.HTTP_REQUEST,
        description="Probe request with auth header",
        request_metadata={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken",
            "password": "SuperSecretPassword123!",
            "normal_header": "test-val",
        },
        raw_data="User password was password=SuperSecretPassword123! in request body",
        observed_behavior="Server accepted token with token=abcdef123456",
    )

    assert len(collection.items) == 1
    assert item.request_metadata["Authorization"] == "[REDACTED]"
    assert item.request_metadata["password"] == "[REDACTED]"
    assert item.request_metadata["normal_header"] == "test-val"
    assert "SuperSecretPassword123!" not in item.raw_data
    assert "[REDACTED]" in item.raw_data

    summary_str = collection.to_summary_string()
    assert "[HTTP_REQUEST]" in summary_str
    assert "SuperSecretPassword123!" not in summary_str


def test_finding_lifecycle_transitions(sample_findings_base: list[Finding]):
    """Verify FindingLifecycleManager handles initial, repeated, and reopened transitions."""
    manager = FindingLifecycleManager()

    # 1. First scan baseline
    aligned = manager.align_lifecycle(sample_findings_base, target_url="https://example.com")
    assert len(aligned) == 3
    assert aligned[0].target_url == "https://example.com"

    # 2. Candidate scan where:
    # - f1 (XSS) is observed again
    # - f3 (CORS, previously RESOLVED) reappears -> must become REOPENED
    # - f4 (SQLi) is brand new
    f1_retest = Finding(
        scanner="xss",
        category="Cross-Site Scripting",
        title="Reflected XSS in search",
        severity=FindingSeverity.HIGH,
        confidence=90,
        endpoint_url="https://example.com/search",
        parameter_name="q",
        description="Reflected XSS in search parameter",
    )
    f3_reopened = Finding(
        scanner="cors",
        category="CORS",
        title="Insecure CORS Wildcard",
        severity=FindingSeverity.MEDIUM,
        confidence=85,
        endpoint_url="https://example.com/api/data",
        description="Access-Control-Allow-Origin: *",
    )
    f4_new = Finding(
        scanner="sqli",
        category="SQL Injection",
        title="Error-Based SQL Injection",
        severity=FindingSeverity.CRITICAL,
        confidence=95,
        endpoint_url="https://example.com/login",
        parameter_name="user",
        description="SQL syntax error returned",
    )

    current_scan = [f1_retest, f3_reopened, f4_new]
    aligned_retest = manager.align_lifecycle(current_scan, historical_findings=sample_findings_base)

    status_by_scanner = {f.scanner: f.status for f in aligned_retest}
    assert status_by_scanner["xss"] == FindingStatus.CONFIRMED
    assert status_by_scanner["cors"] == FindingStatus.REOPENED
    assert status_by_scanner["sqli"] == FindingStatus.CONFIRMED

    # 3. Detect resolved (f2 Missing CSP Header was fixed and absent in current scan)
    resolved_list = manager.detect_resolved(current_scan, sample_findings_base)
    assert len(resolved_list) == 1
    assert resolved_list[0].scanner == "security_headers"
    assert resolved_list[0].status == FindingStatus.RESOLVED


def test_security_regression_engine(sample_findings_base: list[Finding]):
    """Verify regression engine detects NEW, RESOLVED, UNCHANGED, and REOPENED flaws."""
    engine = SecurityRegressionEngine()

    f1_retest = Finding(
        scanner="xss",
        category="Cross-Site Scripting",
        title="Reflected XSS in search",
        severity=FindingSeverity.HIGH,
        confidence=90,
        endpoint_url="https://example.com/search",
        parameter_name="q",
        description="Reflected XSS in search parameter",
    )
    f3_reopened = Finding(
        scanner="cors",
        category="CORS",
        title="Insecure CORS Wildcard",
        severity=FindingSeverity.HIGH,  # Escalated severity
        confidence=85,
        endpoint_url="https://example.com/api/data",
        description="Access-Control-Allow-Origin: *",
    )
    f4_new = Finding(
        scanner="sqli",
        category="SQL Injection",
        title="Error-Based SQL Injection",
        severity=FindingSeverity.CRITICAL,
        confidence=95,
        endpoint_url="https://example.com/login",
        parameter_name="user",
        description="SQL syntax error returned",
    )

    current_scan = [f1_retest, f3_reopened, f4_new]

    report = engine.evaluate_regression(
        baseline_scan_id="scan-base-001",
        current_scan_id="scan-curr-002",
        baseline_findings=sample_findings_base,
        current_findings=current_scan,
        baseline_endpoints=["/", "/search", "/api/data"],
        current_endpoints=["/", "/search", "/api/data", "/login", "/admin"],
        target_url="https://example.com",
    )

    summary = report.summary()
    assert summary["baseline_scan_id"] == "scan-base-001"
    assert summary["current_scan_id"] == "scan-curr-002"
    assert summary["new"] == 1  # SQLi
    assert summary["resolved"] == 1  # Missing CSP
    assert summary["unchanged"] == 1  # XSS
    assert summary["reopened"] == 1  # CORS
    assert summary["new_endpoints_count"] == 2  # /login, /admin
    assert report.has_blocking_regressions is True  # CORS was reopened as HIGH


def test_cli_regression_command(mocker):
    """Verify CLI `vulnforge regression` command with mocked database returns."""
    runner = CliRunner()

    mocker.patch(
        "vulnforge.cli.main.cmd_regression",
        return_value=0,
    )

    result = runner.invoke(app, ["regression", "scan-1", "scan-2"])
    assert result.exit_code == 0
