"""Attack surface aggregator, builder, and intelligence coordinator."""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from vulnforge.intelligence.endpoints import EndpointClassifier
from vulnforge.intelligence.models import (
    AttackSurface,
    EndpointClassification,
    ParameterClassification,
    PriorityLevel,
)
from vulnforge.intelligence.parameters import ParameterClassifier
from vulnforge.intelligence.prioritizer import EndpointPrioritizer
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter


HIGH_INTEREST_PARAM_CLASSES: Set[str] = {
    ParameterClassification.IDENTIFIER.value,
    ParameterClassification.AUTHENTICATION.value,
    ParameterClassification.REDIRECT.value,
    ParameterClassification.URL_INPUT.value,
    ParameterClassification.FILE_PATH.value,
    ParameterClassification.FILE_NAME.value,
    ParameterClassification.STATE_CHANGE.value,
}


class AttackSurfaceBuilder:
    """Builds, enriches, and structures the overall target attack surface."""

    @classmethod
    def build(
        cls,
        target_url: str,
        endpoints: List[Endpoint],
        parameters: Optional[List[Parameter]] = None,
        forms: Optional[List[Dict[str, Any]]] = None,
        javascript_assets: Optional[List[str]] = None,
        technologies: Optional[List[Dict[str, Any]]] = None,
    ) -> AttackSurface:
        """Construct a fully classified and prioritized AttackSurface instance.

        Args:
            target_url: Root target assessed.
            endpoints: Discovered endpoint models.
            parameters: Discovered parameter models.
            forms: Extracted HTML forms metadata.
            javascript_assets: Discovered JavaScript file URLs.
            technologies: Identified technologies metadata.

        Returns:
            AttackSurface domain model.
        """
        params_list = list(parameters or [])
        all_hosts: Set[str] = set()
        parsed_target = urlparse(target_url)
        if parsed_target.hostname:
            all_hosts.add(parsed_target.hostname.lower())

        # 1. Classify all parameters
        for p in params_list:
            if p.classification == "UNKNOWN" or not p.classification:
                res = ParameterClassifier.classify(p)
                p.classification = res.classification.value
                p.classification_confidence = res.confidence

        # 2. Classify and prioritize all endpoints
        classification_counts: Dict[str, int] = defaultdict(int)
        for ep in endpoints:
            if ep.host:
                all_hosts.add(ep.host.lower())

            # Classify endpoint
            ep_classes = EndpointClassifier.classify(ep)
            ep.classifications = [c.value for c in ep_classes]
            for c in ep.classifications:
                classification_counts[c] += 1

            # Prioritize endpoint
            priority = EndpointPrioritizer.prioritize(ep)
            ep.priority_score = priority.score
            ep.priority_level = priority.priority_level.value
            ep.priority_reasons = priority.reasons
            ep.risk_indicators = priority.indicators

        # 3. Sort endpoints by priority score descending
        sorted_endpoints = sorted(endpoints, key=lambda e: e.priority_score, reverse=True)

        # 4. Filter API endpoints
        api_endpoints = [
            ep for ep in sorted_endpoints
            if EndpointClassification.API.value in ep.classifications or ep.is_api
        ]

        # 5. Count High Priority Inputs
        high_priority_inputs = 0
        for p in params_list:
            if p.classification in HIGH_INTEREST_PARAM_CLASSES:
                high_priority_inputs += 1

        return AttackSurface(
            target_url=target_url,
            hosts=sorted(list(all_hosts)),
            endpoints=sorted_endpoints,
            parameters=params_list,
            forms=forms or [],
            api_endpoints=api_endpoints,
            javascript_assets=javascript_assets or [],
            technologies=technologies or [],
            classifications=dict(classification_counts),
            high_priority_inputs_count=high_priority_inputs,
            total_endpoints=len(sorted_endpoints),
            total_parameters=len(params_list),
        )

    @classmethod
    def get_scanner_recommendations(cls, endpoint: Endpoint) -> List[str]:
        """Map endpoint classifications to suggested relevant scanner modules."""
        recs = set()
        classes = set(endpoint.classifications)

        if EndpointClassification.STATIC_ASSET.value in classes:
            return ["security-headers"]

        # Default foundational scanners for active pages
        recs.add("security-headers")
        recs.add("information-disclosure")

        if EndpointClassification.API.value in classes:
            recs.add("cors")
            recs.add("endpoint-inspector")

        if EndpointClassification.REDIRECT_CANDIDATE.value in classes:
            recs.add("open-redirect")

        if EndpointClassification.SEARCH.value in classes or EndpointClassification.DYNAMIC_ROUTE.value in classes:
            recs.add("xss")
            recs.add("sqli")

        if EndpointClassification.FILE_UPLOAD_CANDIDATE.value in classes:
            recs.add("file-upload")
            recs.add("directory-traversal")

        if EndpointClassification.STATE_CHANGING.value in classes:
            recs.add("csrf")

        if EndpointClassification.IDENTIFIER_ENDPOINT.value in classes:
            recs.add("sqli")

        return sorted(list(recs))
