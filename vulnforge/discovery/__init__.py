"""VulnForge discovery and reconnaissance engines."""

from vulnforge.discovery.endpoints import EndpointInventory
from vulnforge.discovery.javascript import (
    JsDiscoveryResult,
    extract_endpoints_from_js,
)
from vulnforge.discovery.parameters import (
    INTERESTING_PARAM_CATEGORIES,
    ParameterInventory,
    categorize_parameter,
)
from vulnforge.discovery.technologies import (
    TechnologyDetection,
    TechnologyFingerprinter,
)

__all__ = [
    "EndpointInventory",
    "ParameterInventory",
    "categorize_parameter",
    "INTERESTING_PARAM_CATEGORIES",
    "JsDiscoveryResult",
    "extract_endpoints_from_js",
    "TechnologyDetection",
    "TechnologyFingerprinter",
]
