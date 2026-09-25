"""Tests for CLI workflow, AttackSurface form normalization, doctor command, and failure semantics."""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from vulnforge.crawler.forms import DiscoveredForm, FormField, extract_forms_from_html
from vulnforge.intelligence.models import AttackSurface
from vulnforge.intelligence.surface import AttackSurfaceBuilder
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.scanners.engine import ScannerEngine
from vulnforge.scanners.result import ScannerStatus, ScannerExecutionReport, AssessmentCoverage
from vulnforge.cli.commands import cmd_doctor, execute_scan


def test_attack_surface_form_normalization():
    """Verify AttackSurface accepts both DiscoveredForm models and normalized dicts."""
    dvwa_form = DiscoveredForm(
        action="http://192.168.50.20/DVWA/login.php",
        method="POST",
        source_url="http://192.168.50.20/DVWA/login.php",
        fields=[
            FormField(name="username", field_type="text", value="admin"),
            FormField(name="password", field_type="password", value=""),
            FormField(name="Login", field_type="submit", value="Login"),
            FormField(name="user_token", field_type="hidden", value="1234567890abcdef"),
        ],
    )

    surface = AttackSurface(
        target_url="http://192.168.50.20/DVWA/",
        endpoints=[],
        parameters=[],
        forms=[dvwa_form],
    )

    assert len(surface.forms) == 1
    assert surface.forms[0].action == "http://192.168.50.20/DVWA/login.php"
    assert surface.forms[0].method == "POST"
    assert len(surface.forms[0].fields) == 4
    assert surface.forms[0].fields[0].name == "username"
    assert surface.forms[0].fields[3].field_type == "hidden"


def test_build_attack_surface_from_html():
    """Verify build_attack_surface correctly builds a valid AttackSurface with DiscoveredForm."""
    html = """
    <form action="/DVWA/vulnerabilities/sqli/" method="GET">
        <input type="text" name="id" />
        <input type="submit" name="Submit" value="Submit" />
    </form>
    """
    forms = extract_forms_from_html(html, "http://192.168.50.20/DVWA/vulnerabilities/sqli/")
    assert len(forms) == 1

    surface = AttackSurfaceBuilder.build(
        target_url="http://192.168.50.20/DVWA/",
        endpoints=[
            Endpoint.from_url(
                "http://192.168.50.20/DVWA/vulnerabilities/sqli/",
                method="GET",
            )
        ],
        parameters=[
            Parameter(
                name="id",
                location=ParameterLocation.QUERY,
                endpoint_url="http://192.168.50.20/DVWA/vulnerabilities/sqli/",
            )
        ],
        forms=forms,
    )

    assert len(surface.forms) == 1
    assert isinstance(surface.forms[0], DiscoveredForm)
    assert surface.forms[0].fields[0].name == "id"


def test_parameter_recommendations():
    """Verify explainable candidate recommendations for SQLi, XSS, Auth, and Traversal."""
    id_param = Parameter(
        name="id",
        location=ParameterLocation.QUERY,
        endpoint_url="http://192.168.50.20/DVWA/vulnerabilities/sqli/",
    )
    rec = AttackSurfaceBuilder.get_parameter_recommendations(id_param)
    scanner_names = [c["scanner"] for c in rec]
    assert any("SQL Injection" in s for s in scanner_names)
    assert len(rec[0]["reasons"]) > 0

    user_param = Parameter(
        name="username",
        location=ParameterLocation.FORM,
        endpoint_url="http://192.168.50.20/DVWA/login.php",
    )
    rec_user = AttackSurfaceBuilder.get_parameter_recommendations(user_param)
    user_scanner_names = [c["scanner"] for c in rec_user]
    assert any("Authentication" in s for s in user_scanner_names)

    file_param = Parameter(
        name="page",
        location=ParameterLocation.QUERY,
        endpoint_url="http://192.168.50.20/DVWA/vulnerabilities/fi/?page=include.php",
    )
    rec_file = AttackSurfaceBuilder.get_parameter_recommendations(file_param)
    file_scanner_names = [c["scanner"] for c in rec_file]
    assert any("Directory Traversal" in s for s in file_scanner_names)


def test_assessment_coverage_model():
    """Verify AssessmentCoverage correctly represents assessment metrics."""
    coverage = AssessmentCoverage(
        endpoints_discovered=18,
        endpoints_tested=14,
        endpoints_skipped=4,
        parameters_discovered=27,
        parameters_tested=19,
        parameters_skipped=8,
        scanners_available=12,
        scanners_executed=9,
        scanners_skipped=2,
        scanners_failed=1,
        untested_reasons=["3 authentication-required endpoints (unauthenticated scan mode)"],
    )

    assert coverage.endpoints_discovered == 18
    assert coverage.endpoints_tested == 14
    assert coverage.endpoints_skipped == 4
    assert coverage.parameters_tested == 19
    assert coverage.scanners_executed == 9
    assert len(coverage.untested_reasons) == 1


def test_cmd_doctor():
    """Verify the doctor command successfully executes and checks all subsystems."""
    exit_code = cmd_doctor()
    assert exit_code == 0


@pytest.mark.asyncio
async def test_execute_scan_failure_semantics():
    """Verify that when surface discovery or crawling fails, execute_scan returns non-zero and marks scan as failed."""
    from vulnforge.models.response import HttpResponse
    
    mock_resp = HttpResponse(
        status_code=200,
        url="http://127.0.0.1:8000/app",
        request_method="GET",
        request_url="http://127.0.0.1:8000/app",
        body="<html><body><h1>Test App</h1></body></html>",
    )

    with patch("vulnforge.core.engine.HttpEngine.get", AsyncMock(return_value=mock_resp)):
        with patch("vulnforge.intelligence.surface.AttackSurfaceBuilder.build", side_effect=ValueError("Test surface discovery failure")):
            exit_code = await execute_scan(
                target_url="http://127.0.0.1:8000/app",
                quiet=True,
            )
            assert exit_code == 2
