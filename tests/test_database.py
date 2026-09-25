"""Tests for SQLite database persistence."""

import pytest
from vulnforge.core.config import VulnForgeConfig
from vulnforge.core.context import ScanContext, ScanStatistics
from vulnforge.models.target import Target
from vulnforge.storage.database import DatabaseManager


def test_database_initialization_and_saving():
    """Verify SQLite database creates tables and stores scan and target metadata."""
    db = DatabaseManager(":memory:")
    target = Target.from_url("https://example.com")
    context = ScanContext(target=target)

    # Save scan
    db.save_scan(context, status="running")

    # Retrieve scan
    record = db.get_scan(context.scan_id)
    assert record is not None
    assert record["target_url"] == "https://example.com"
    assert record["status"] == "running"


def test_database_update_stats():
    """Verify updating scan status and metrics in database."""
    db = DatabaseManager(":memory:")
    target = Target.from_url("https://example.com")
    context = ScanContext(target=target)

    db.save_scan(context, status="running")

    # Simulate some stats
    context.stats.record_request_sent()
    context.stats.record_success()
    context.stats.record_blocked()

    db.update_scan_status(context.scan_id, status="completed", stats=context.stats)

    record = db.get_scan(context.scan_id)
    assert record["status"] == "completed"
    assert record["requests_sent"] == 1
    assert record["requests_successful"] == 1
    assert record["requests_blocked"] == 1


def test_database_log_http_requests():
    """Verify logging individual HTTP transactions."""
    db = DatabaseManager(":memory:")
    target = Target.from_url("https://example.com")
    context = ScanContext(target=target)
    db.save_scan(context)

    db.log_http_request(
        scan_id=context.scan_id,
        method="GET",
        url="https://example.com/api",
        status_code=200,
        elapsed_ms=45.2,
    )

    scans = db.list_scans()
    assert len(scans) == 1
