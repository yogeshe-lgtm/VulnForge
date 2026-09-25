"""Unit and integration tests for OAST, Fuzzing, ProxyAdapter, CI/CD, and SARIF 2.1.0."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from vulnforge.fuzz.engine import ControlledFuzzer
from vulnforge.fuzz.models import FuzzMode
from vulnforge.integrations.proxy import ProxyAdapter
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.response import HttpResponse
from vulnforge.oast.models import CallbackEvent
from vulnforge.oast.provider import SelfHostedOASTProvider
from vulnforge.reporting.sarif import SARIFReportGenerator
from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus


def test_oast_token_generation_and_correlation():
    provider = SelfHostedOASTProvider(base_domain="oast.local")
    canary = provider.create_canary(
        scanner_name="sqli-oast",
        target_url="https://example.com/api/search",
        parameter_name="query",
    )

    assert canary.token_id.startswith("VF-")
    assert canary.token_id.lower() in canary.callback_url
    assert "oast.local" in canary.callback_url

    # Simulate callback event
    event = CallbackEvent(
        token_id=canary.token_id,
        protocol="DNS",
        client_ip="192.168.1.100",
        raw_query=f"{canary.token_id.lower()}.oast.local",
    )
    provider.record_local_event(event)

    findings = provider.correlate()
    assert len(findings) == 1
    assert findings[0].severity == FindingSeverity.CRITICAL
    assert findings[0].confidence == 100
    assert "DNS" in findings[0].title
    assert canary.target_url == findings[0].endpoint_url


@pytest.mark.asyncio
async def test_controlled_fuzzer_execution():
    mock_http = MagicMock()

    async def mock_get(url, **kwargs):
        if "admin" in url:
            return HttpResponse(
                url=url,
                request_url=url,
                request_method="GET",
                status_code=403,
                headers={"content-type": "text/html"},
                body="Forbidden",
                elapsed=0.03,
            )
        elif "api" in url:
            return HttpResponse(
                url=url,
                request_url=url,
                request_method="GET",
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"status": "ok"}',
                elapsed=0.02,
            )
        return HttpResponse(
            url=url,
            request_url=url,
            request_method="GET",
            status_code=404,
            headers={"content-type": "text/html"},
            body="Not Found",
            elapsed=0.02,
        )

    mock_http.get = AsyncMock(side_effect=mock_get)

    fuzzer = ControlledFuzzer(max_requests=10, concurrency=2, delay_ms=0)
    wordlist = ["admin", "api", "nonexistent1", "nonexistent2"]

    summary = await fuzzer.fuzz_endpoints(
        http_client=mock_http,
        target_base_url="https://example.com",
        wordlist=wordlist,
    )

    assert summary.total_requests_sent == 4
    assert summary.discovered_endpoints_count == 2
    assert 403 in summary.status_distribution
    assert 200 in summary.status_distribution
    assert len(summary.results) == 2


def test_proxy_adapter_har_import_export():
    sample_har = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/v1/users?page=1",
                    },
                    "response": {"status": 200},
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/api/v1/login",
                    },
                    "response": {"status": 302},
                },
            ],
        }
    }

    endpoints = ProxyAdapter.import_har_endpoints(json.dumps(sample_har))
    assert len(endpoints) == 2
    assert endpoints[0].url == "https://example.com/api/v1/users?page=1"
    assert endpoints[0].method == "GET"
    assert endpoints[1].url == "https://example.com/api/v1/login"
    assert endpoints[1].method == "POST"

    # Test export
    exported = ProxyAdapter.export_har(endpoints)
    assert "log" in exported
    assert len(exported["log"]["entries"]) == 2
    assert exported["log"]["entries"][0]["request"]["url"] == endpoints[0].url


def test_sarif_210_report_generation():
    finding = Finding(
        scanner="xss",
        category="Cross-Site Scripting",
        title="Reflected Cross-Site Scripting (XSS)",
        severity=FindingSeverity.HIGH,
        confidence=90,
        status=FindingStatus.CONFIRMED,
        endpoint_url="https://example.com/search?q=test",
        parameter_name="q",
        description="Query parameter 'q' reflected without HTML sanitization.",
        evidence="q=<script>alert(1)</script>",
        recommendation="Context-aware HTML entity encoding.",
        references=["https://owasp.org/www-community/attacks/xss/"],
    )

    sarif_dict = SARIFReportGenerator.generate_sarif(
        findings=[finding],
        target_url="https://example.com",
    )

    assert sarif_dict["version"] == "2.1.0"
    assert "$schema" in sarif_dict
    assert len(sarif_dict["runs"]) == 1

    run = sarif_dict["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnForge"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com/search?q=test"
