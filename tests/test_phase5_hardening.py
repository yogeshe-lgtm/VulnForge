"""Comprehensive Phase 5 Hardening and End-to-End Tests for VulnForge."""

import asyncio
from pathlib import Path
import tempfile
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from vulnforge.core.config import VulnForgeConfig, load_config, save_config, PROFILE_PRESETS
from vulnforge.core.context import ScanContext
from vulnforge.core.engine import HttpEngine
from vulnforge.core.exceptions import ConnectionFailedError, RequestTimeoutError, ScopeViolationError
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.correlation.engine import CorrelationEngine
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.models.response import HttpResponse
from vulnforge.models.target import Target
from vulnforge.scanners import (
    AnalysisContext,
    CORSScanner,
    CSRFScanner,
    DirectoryTraversalScanner,
    EndpointInspectorScanner,
    FileUploadScanner,
    FindingSeverity,
    FindingStatus,
    InformationDisclosureScanner,
    OpenRedirectScanner,
    SQLiScanner,
    ScannerEngine,
    ScannerMode,
    ScannerRegistry,
    SecurityHeadersScanner,
    XSSScanner,
)
from vulnforge.storage.database import DatabaseManager
from vulnforge.utils.redaction import redact_secrets, redact_dict_secrets


class TestProfilesAndHierarchy:
    """Test configuration profiles and hierarchical loading."""

    def test_profile_presets_exist(self):
        for prof in ["passive", "safe", "balanced", "custom"]:
            assert prof in PROFILE_PRESETS

    def test_load_passive_profile(self):
        cfg = load_config(profile_name="passive")
        assert cfg.default_rate == 10.0
        assert cfg.crawl_depth == 2
        assert "security-headers" in cfg.enabled_scanners

    def test_load_balanced_profile(self):
        cfg = load_config(profile_name="balanced")
        assert cfg.default_rate == 15.0
        assert cfg.default_threads == 8
        assert cfg.crawl_depth == 4

    def test_project_config_overrides_user_config(self, tmp_path: Path):
        user_cfg_file = tmp_path / "user_config.toml"
        proj_cfg_file = tmp_path / "vulnforge.toml"

        user_cfg = VulnForgeConfig(default_rate=2.0, default_threads=3)
        save_config(user_cfg, config_path=user_cfg_file)

        # Project config
        with open(proj_cfg_file, "w", encoding="utf-8") as f:
            f.write('default_rate = 9.0\ndefault_threads = 12\n')

        with patch("vulnforge.core.config.get_project_config_path", return_value=proj_cfg_file):
            loaded = load_config(config_path=user_cfg_file, profile_name="custom")
            assert loaded.default_rate == 9.0
            assert loaded.default_threads == 12


class TestScannerRegistryFiltering:
    """Test filtering scanners by comma-separated tokens, names, and categories."""

    def test_filter_by_name(self):
        filtered = ScannerRegistry.filter(include=["xss"])
        assert any(s.name == "xss" for s in filtered)

    def test_filter_by_comma_separated_string(self):
        filtered = ScannerRegistry.filter(include=["xss,sqli,cors"])
        names = {s.name for s in filtered}
        assert "xss" in names
        assert "sqli" in names
        assert "cors" in names

    def test_filter_by_category(self):
        filtered = ScannerRegistry.filter(include=["security headers"])
        assert any(s.name == "security-headers" for s in filtered)

    def test_exclude_scanners(self):
        filtered = ScannerRegistry.filter(exclude=["xss", "sqli"])
        names = {s.name for s in filtered}
        assert "xss" not in names
        assert "sqli" not in names


class TestModularScanners:
    """Test individual security assessment scanners against mock responses."""

    @pytest.mark.asyncio
    async def test_security_headers_scanner(self):
        scanner = SecurityHeadersScanner()
        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=HttpResponse(
            status_code=200,
            url="https://example.com/",
            headers={"Server": "nginx"},  # Missing CSP, HSTS, X-Frame-Options
            body="<html>OK</html>",
            raw_bytes=b"<html>OK</html>",
            elapsed=0.1,
            request_method="GET",
            request_url="https://example.com/",
            request_headers={},
            history=[],
        ))

        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) >= 3  # Missing headers observed
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert len(findings) >= 3
        assert any("Content-Security-Policy" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_information_disclosure_scanner(self):
        scanner = InformationDisclosureScanner()
        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=HttpResponse(
            status_code=500,
            url="https://example.com/api",
            headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
            body="Traceback (most recent call last):\n  File 'app.py', line 42, in index\nZeroDivisionError",
            raw_bytes=b"error",
            elapsed=0.1,
            request_method="GET",
            request_url="https://example.com/api",
            request_headers={},
            history=[],
        ))

        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/api", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) >= 2  # Server banner + stack trace
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert any("Stack Trace" in f.title for f in findings)
        assert any("Version Banner" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_cors_scanner(self):
        scanner = CORSScanner()
        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=HttpResponse(
            status_code=200,
            url="https://example.com/data",
            headers={
                "Access-Control-Allow-Origin": "https://evil-attacker.example",
                "Access-Control-Allow-Credentials": "true",
            },
            body="{}",
            raw_bytes=b"{}",
            elapsed=0.1,
            request_method="GET",
            request_url="https://example.com/data",
            request_headers={},
            history=[],
        ))

        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/data", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) == 1
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH

    @pytest.mark.asyncio
    async def test_open_redirect_scanner(self):
        scanner = OpenRedirectScanner()
        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=HttpResponse(
            status_code=302,
            url="https://example.com/login?redirect=https://example.com",
            headers={"Location": "https://example.com"},
            body="",
            raw_bytes=b"",
            elapsed=0.1,
            request_method="GET",
            request_url="https://example.com/login",
            request_headers={},
            history=[],
        ))

        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/login?redirect=dashboard", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) == 1
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert len(findings) == 1
        assert "Open URL Redirection" in findings[0].title

    @pytest.mark.asyncio
    async def test_xss_scanner(self):
        scanner = XSSScanner()
        mock_http = MagicMock()
        
        async def mock_get(url, **kwargs):
            if "%3Cxss%3E" in url or "<xss>" in url or "99" in url:
                body = "<div>Search result for: vf\"<xss>'99</div>"
            elif "vfprobe_xss123" in url:
                body = "<div>Search result for: vfprobe_xss123</div>"
            else:
                body = "<div>Search</div>"
            return HttpResponse(
                status_code=200,
                url=url,
                headers={},
                body=body,
                raw_bytes=body.encode("utf-8"),
                elapsed=0.1,
                request_method="GET",
                request_url=url,
                request_headers={},
                history=[],
            )

        mock_http.get = AsyncMock(side_effect=mock_get)
        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/search?q=test", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) == 2  # Reflected input + unencoded context
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert len(findings) == 1
        assert "Reflected Cross-Site Scripting" in findings[0].title
        assert findings[0].severity == FindingSeverity.HIGH

    @pytest.mark.asyncio
    async def test_sqli_scanner(self):
        scanner = SQLiScanner()
        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=HttpResponse(
            status_code=500,
            url="https://example.com/user?id=1'",
            headers={},
            body="Error: You have an error in your SQL syntax near ''' at line 1",
            raw_bytes=b"sql error",
            elapsed=0.1,
            request_method="GET",
            request_url="https://example.com/user",
            request_headers={},
            history=[],
        ))

        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/user?id=1", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) == 1
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert len(findings) == 1
        assert "SQL Injection" in findings[0].title
        assert findings[0].severity == FindingSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_directory_traversal_scanner(self):
        scanner = DirectoryTraversalScanner()
        mock_http = MagicMock()
        mock_http.get = AsyncMock(return_value=HttpResponse(
            status_code=200,
            url="https://example.com/download?file=../../../../etc/passwd",
            headers={},
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            raw_bytes=b"root:x:0:0",
            elapsed=0.1,
            request_method="GET",
            request_url="https://example.com/download",
            request_headers={},
            history=[],
        ))

        target = Target.from_url("https://example.com")
        ctx = AnalysisContext(target=target, http=mock_http)
        endpoint = Endpoint.from_url("https://example.com/download?file=notes.txt", method="GET")

        obs = await scanner.analyze(ctx, endpoint)
        assert len(obs) == 1
        ctx.observations.extend(obs)

        findings = await scanner.finalize(ctx)
        assert len(findings) == 1
        assert "Directory Traversal" in findings[0].title
        assert findings[0].severity == FindingSeverity.HIGH


class TestSecurityAndRedaction:
    """Verify tool security self-audit and secret sanitization."""

    def test_redaction_patterns(self):
        sensitive_text = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret\n"
            "Cookie: session=secret_cookie_12345; user=admin\n"
            "api_key=test_secret_token_1234567890abcdef\n"
            "aws_key=AKIAIOSFODNN7EXAMPLE"
        )
        scrubbed = redact_secrets(sensitive_text)
        assert "eyJhbGciOi" not in scrubbed
        assert "test_secret_token" not in scrubbed
        assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
        assert "[REDACTED]" in scrubbed

    def test_dict_redaction(self):
        headers = {
            "Authorization": "Bearer secret-token-xyz",
            "Cookie": "session=abc12345",
            "Content-Type": "application/json",
        }
        scrubbed = redact_dict_secrets(headers)
        assert scrubbed["Authorization"] == "[REDACTED]"
        assert scrubbed["Cookie"] == "[REDACTED]"
        assert scrubbed["Content-Type"] == "application/json"


class TestEndToEndMockScan:
    """End-to-end integration test of the full workflow."""

    @pytest.mark.asyncio
    async def test_full_pipeline_synthesis(self, tmp_path: Path):
        db_path = str(tmp_path / "test_scan.db")
        target = Target.from_url("http://127.0.0.1:8080", scan_profile="safe", allow_private=True)
        scope = ScopeEngine(allowed_domains=target.scope)
        rate = RateLimiter(rate=50.0, concurrency=10)
        cfg = VulnForgeConfig(database_path=db_path)

        scan_context = ScanContext(target=target, config=cfg, scope=scope, rate_limiter=rate)
        db = DatabaseManager(db_path)
        db.save_scan(scan_context)

        # Mock endpoints
        endpoints = [
            Endpoint.from_url("http://127.0.0.1:8080/", method="GET", status_code=200),
            Endpoint.from_url("http://127.0.0.1:8080/search?q=test", method="GET", status_code=200),
        ]
        db.save_endpoints(scan_context.scan_id, endpoints)

        # Execute scanners
        engine = ScannerEngine()
        raw_obs, raw_findings = await engine.run(
            scan_context=scan_context,
            endpoints=endpoints,
            include_scanners=["endpoint-inspector"],
        )

        corr_engine = CorrelationEngine()
        findings = corr_engine.correlate(raw_obs, raw_findings)

        db.save_observations(scan_context.scan_id, raw_obs)
        db.save_findings(scan_context.scan_id, findings)
        db.update_scan_status(scan_context.scan_id, "completed", scan_context.stats)

        # Verify database records
        saved_scan = db.get_scan(scan_context.scan_id)
        assert saved_scan["status"] == "completed"
        saved_findings = db.get_findings(scan_context.scan_id)
        assert isinstance(saved_findings, list)
