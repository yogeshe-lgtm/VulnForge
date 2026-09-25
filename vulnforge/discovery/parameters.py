"""Parameter discovery, categorization, and analysis."""

from collections import defaultdict
from typing import Dict, List, Set

from vulnforge.models.parameter import Parameter, ParameterLocation


# High-interest parameter names often targeted during security assessments
INTERESTING_PARAM_CATEGORIES: Dict[str, Set[str]] = {
    "identifier": {"id", "user_id", "userid", "account_id", "uid", "item_id", "uuid", "guid", "doc_id"},
    "authentication": {"token", "auth", "access_token", "api_key", "apikey", "session", "jwt", "secret", "password"},
    "redirection": {"redirect", "url", "next", "return", "return_to", "dest", "destination", "goto", "out", "target"},
    "search_query": {"q", "query", "search", "keyword", "term", "find", "filter"},
    "pagination": {"page", "limit", "offset", "count", "start", "per_page", "size"},
    "file_handling": {"file", "path", "filename", "folder", "doc", "document", "upload", "download", "dir"},
    "command_exec": {"cmd", "exec", "command", "run", "ping", "host", "ip"},
}


def categorize_parameter(name: str) -> str:
    """Categorize parameter by security interest based on common conventions."""
    lower_name = name.lower()
    for category, param_set in INTERESTING_PARAM_CATEGORIES.items():
        if lower_name in param_set or any(lower_name.endswith("_" + p) for p in param_set):
            return category
    return "general"


class ParameterInventory:
    """Maintains and deduplicates discovered parameter assets across endpoints."""

    def __init__(self):
        self._parameters: Dict[str, Parameter] = {}
        self._by_endpoint: Dict[str, List[Parameter]] = defaultdict(list)
        self._by_name: Dict[str, List[Parameter]] = defaultdict(list)

    def add(self, param: Parameter) -> bool:
        """Add parameter to inventory.

        Returns:
            True if newly added, False if already present.
        """
        ident = param.identifier
        if ident in self._parameters:
            return False

        self._parameters[ident] = param
        self._by_endpoint[param.endpoint_url].append(param)
        self._by_name[param.name].append(param)
        return True

    def get_all(self) -> List[Parameter]:
        """Return all unique discovered parameters."""
        return list(self._parameters.values())

    def get_by_endpoint(self, endpoint_url: str) -> List[Parameter]:
        """Return all parameters associated with a given endpoint."""
        return self._by_endpoint.get(endpoint_url, [])

    def get_by_location(self, location: ParameterLocation) -> List[Parameter]:
        """Return all parameters for a given location (e.g. query, form)."""
        return [p for p in self._parameters.values() if p.location == location]

    @property
    def total_count(self) -> int:
        """Total number of unique parameters."""
        return len(self._parameters)
