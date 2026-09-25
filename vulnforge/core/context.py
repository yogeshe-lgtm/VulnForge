"""Scan Context and Runtime Statistics."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional
import uuid

from vulnforge.core.config import VulnForgeConfig
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine

if TYPE_CHECKING:
    from vulnforge.core.engine import HttpEngine
    from vulnforge.models.target import Target


@dataclass
class ScanStatistics:
    """Live statistics tracked across a scan session."""

    requests_sent: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    requests_blocked: int = 0
    http_errors: int = 0
    timeouts: int = 0
    redirects: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def start(self) -> None:
        """Mark scan start timestamp."""
        if not self.start_time:
            self.start_time = datetime.now(timezone.utc)

    def finish(self) -> None:
        """Mark scan end timestamp."""
        self.end_time = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float:
        """Calculate total duration in seconds."""
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now(timezone.utc)
        return max(0.0, (end - self.start_time).total_seconds())

    @property
    def duration_formatted(self) -> str:
        """Format duration as HH:MM:SS or MM:SS."""
        secs = int(self.duration_seconds)
        mins, s = divmod(secs, 60)
        hrs, m = divmod(mins, 60)
        if hrs > 0:
            return f"{hrs:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def record_request_sent(self) -> None:
        """Record an outbound request attempt."""
        self.requests_sent += 1

    def record_success(self) -> None:
        """Record a successful HTTP 2xx response."""
        self.requests_successful += 1

    def record_blocked(self) -> None:
        """Record a request blocked by the scope engine."""
        self.requests_blocked += 1

    def record_failed(self) -> None:
        """Record a network/connection failure."""
        self.requests_failed += 1

    def record_timeout(self) -> None:
        """Record a request timeout."""
        self.timeouts += 1
        self.requests_failed += 1

    def record_http_error(self) -> None:
        """Record an HTTP error status code (4xx or 5xx)."""
        self.http_errors += 1

    def record_redirect(self) -> None:
        """Record an HTTP redirect."""
        self.redirects += 1


class ScanContext:
    """Encapsulates the complete runtime environment, engines, target, and state for a scan."""

    def __init__(
        self,
        target: Target,
        config: Optional[VulnForgeConfig] = None,
        scope: Optional[ScopeEngine] = None,
        rate_limiter: Optional[RateLimiter] = None,
        scan_id: Optional[str] = None,
    ):
        """Initialize ScanContext.

        Args:
            target: Validated scan target.
            config: Tool configuration.
            scope: Configured scope engine.
            rate_limiter: Configured rate limiter.
            scan_id: Optional UUID string.
        """
        self.scan_id: str = scan_id or str(uuid.uuid4())
        self.target: Target = target
        self.config: VulnForgeConfig = config or VulnForgeConfig()

        # Initialize scope from target if not explicitly provided
        if scope is None:
            self.scope = ScopeEngine(allowed_domains=target.scope)
        else:
            self.scope = scope

        # Initialize rate limiter
        if rate_limiter is None:
            self.rate_limiter = RateLimiter(
                rate=self.config.default_rate,
                concurrency=self.config.default_threads,
            )
        else:
            self.rate_limiter = rate_limiter

        self.stats: ScanStatistics = ScanStatistics()
        self.http_engine: Optional["HttpEngine"] = None
        self._is_cancelled: bool = False
        self.custom_data: Dict[str, Any] = {}

    @property
    def is_cancelled(self) -> bool:
        """Check if scan cancellation was requested."""
        return self._is_cancelled

    def cancel(self) -> None:
        """Request graceful scan cancellation."""
        self._is_cancelled = True

    def start(self) -> None:
        """Signal scan start."""
        self.stats.start()

    def finish(self) -> None:
        """Signal scan completion."""
        self.stats.finish()
