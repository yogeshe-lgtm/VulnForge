"""Exceptions for the scanner engine and analysis modules."""

from vulnforge.core.exceptions import VulnForgeException


class ScannerException(VulnForgeException):
    """Base exception for all scanner and analysis errors."""


class ScannerRegistrationError(ScannerException):
    """Raised when scanner registration fails or invalid metadata is provided."""


class ScannerExecutionError(ScannerException):
    """Raised when an analysis module encounters an unhandled runtime error."""
