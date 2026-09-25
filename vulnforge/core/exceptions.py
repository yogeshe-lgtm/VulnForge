"""Structured exception hierarchy for VulnForge."""


class VulnForgeException(Exception):
    """Base exception for all VulnForge errors."""

    def __init__(self, message: str, details: str = ""):
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} ({self.details})"
        return self.message


class ScopeViolationError(VulnForgeException):
    """Raised when an HTTP request or redirect targets an unauthorized out-of-scope resource."""

    def __init__(self, url: str, reason: str = "Destination outside authorized scope"):
        super().__init__(f"[SCOPE BLOCKED] {reason}: {url}", details=f"Target: {url}")
        self.url = url
        self.reason = reason


class TargetValidationError(VulnForgeException):
    """Raised when a scan target fails validation checks."""


class ConfigurationError(VulnForgeException):
    """Raised when configuration loading, parsing, or validation fails."""


class RateLimitExceededError(VulnForgeException):
    """Raised when request rate limit is exceeded."""


class HttpEngineError(VulnForgeException):
    """Base exception for HTTP engine errors."""


class RequestTimeoutError(HttpEngineError):
    """Raised when an HTTP request exceeds the configured timeout."""

    def __init__(self, url: str, timeout: float):
        super().__init__(f"Request timed out after {timeout}s: {url}", details=f"Timeout: {timeout}s")
        self.url = url
        self.timeout = timeout


class ConnectionFailedError(HttpEngineError):
    """Raised when unable to establish connection to target."""

    def __init__(self, url: str, reason: str = ""):
        super().__init__(f"Connection failed to {url}", details=reason)
        self.url = url
        self.reason = reason


class DatabaseError(VulnForgeException):
    """Raised when SQLite storage operations fail."""
