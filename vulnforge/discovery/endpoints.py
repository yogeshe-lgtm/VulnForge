"""Endpoint inventory and attack surface aggregation."""

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter


class EndpointInventory:
    """Manages, aggregates, and categorizes discovered endpoints across all sources."""

    def __init__(self):
        self._endpoints: Dict[Tuple[str, str], Endpoint] = {}
        self._by_source: Dict[str, List[Endpoint]] = defaultdict(list)
        self._by_host: Dict[str, List[Endpoint]] = defaultdict(list)

    def add(self, endpoint: Endpoint) -> bool:
        """Add endpoint to inventory or merge parameters if already known.

        Returns:
            True if newly added, False if merged with existing.
        """
        key = (endpoint.url, endpoint.method.upper())
        if key in self._endpoints:
            existing = self._endpoints[key]
            # Merge parameters
            for param in endpoint.parameters:
                existing.add_parameter(param)
            # Update status code / content type if previously missing
            if endpoint.status_code and not existing.status_code:
                existing.status_code = endpoint.status_code
            if endpoint.content_type and not existing.content_type:
                existing.content_type = endpoint.content_type
            return False

        self._endpoints[key] = endpoint
        self._by_source[endpoint.source].append(endpoint)
        self._by_host[endpoint.host].append(endpoint)
        return True

    def get_all(self) -> List[Endpoint]:
        """Return all unique discovered endpoints."""
        return list(self._endpoints.values())

    def get_api_endpoints(self) -> List[Endpoint]:
        """Return subset of endpoints identified as API routes."""
        return [ep for ep in self._endpoints.values() if ep.is_api]

    def get_by_source(self, source: str) -> List[Endpoint]:
        """Return endpoints discovered by a specific source."""
        return self._by_source.get(source, [])

    @property
    def total_count(self) -> int:
        """Total number of unique endpoints."""
        return len(self._endpoints)

    @property
    def api_count(self) -> int:
        """Number of unique API endpoints."""
        return sum(1 for ep in self._endpoints.values() if ep.is_api)
