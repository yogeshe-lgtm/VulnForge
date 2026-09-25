"""VulnForge modular security scanner framework and registry."""

from vulnforge.scanners.authorization import AuthorizationScanner
from vulnforge.scanners.base import BaseScanner, ScannerMode
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.cors import CORSScanner
from vulnforge.scanners.csrf import CSRFScanner
from vulnforge.scanners.endpoint_inspector import EndpointInspectorScanner
from vulnforge.scanners.engine import ScannerEngine
from vulnforge.scanners.exceptions import (
    ScannerException,
    ScannerExecutionError,
    ScannerRegistrationError,
)
from vulnforge.scanners.file_upload import FileUploadScanner
from vulnforge.scanners.information_disclosure import InformationDisclosureScanner
from vulnforge.scanners.open_redirect import OpenRedirectScanner
from vulnforge.scanners.registry import ScannerRegistry
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
    ResponseDifference,
    compare_responses,
)
from vulnforge.scanners.security_headers import SecurityHeadersScanner
from vulnforge.scanners.sqli import SQLiScanner
from vulnforge.scanners.traversal import DirectoryTraversalScanner
from vulnforge.scanners.xss import XSSScanner

# Register all built-in modular scanners
ScannerRegistry.register(SecurityHeadersScanner())
ScannerRegistry.register(InformationDisclosureScanner())
ScannerRegistry.register(CORSScanner())
ScannerRegistry.register(OpenRedirectScanner())
ScannerRegistry.register(XSSScanner())
ScannerRegistry.register(SQLiScanner())
ScannerRegistry.register(DirectoryTraversalScanner())
ScannerRegistry.register(CSRFScanner())
ScannerRegistry.register(FileUploadScanner())
ScannerRegistry.register(EndpointInspectorScanner())
ScannerRegistry.register(AuthorizationScanner())

__all__ = [
    "BaseScanner",
    "ScannerMode",
    "ScannerRegistry",
    "ScannerEngine",
    "AnalysisContext",
    "Observation",
    "ObservationType",
    "Finding",
    "FindingSeverity",
    "FindingStatus",
    "ResponseDifference",
    "compare_responses",
    "SecurityHeadersScanner",
    "InformationDisclosureScanner",
    "CORSScanner",
    "OpenRedirectScanner",
    "XSSScanner",
    "SQLiScanner",
    "DirectoryTraversalScanner",
    "CSRFScanner",
    "FileUploadScanner",
    "EndpointInspectorScanner",
    "AuthorizationScanner",
    "ScannerException",
    "ScannerRegistrationError",
    "ScannerExecutionError",
]

