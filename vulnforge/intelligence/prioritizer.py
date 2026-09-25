"""Explainable endpoint prioritization engine."""

from typing import List, Optional

from vulnforge.intelligence.endpoints import EndpointClassifier
from vulnforge.intelligence.models import (
    EndpointClassification,
    EndpointPriority,
    PriorityLevel,
)
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter


class EndpointPrioritizer:
    """Computes transparent, explainable priority scores and testing recommendations for endpoints."""

    @classmethod
    def prioritize(
        cls,
        endpoint: Endpoint,
        parameters: Optional[List[Parameter]] = None,
    ) -> EndpointPriority:
        """Calculate the priority score, priority level, and detailed explanation for an endpoint.

        Args:
            endpoint: The Endpoint instance to assess.
            parameters: Associated parameters for this endpoint.

        Returns:
            EndpointPriority object containing score (0-100), level, and human-readable reasons.
        """
        params = parameters if parameters is not None else endpoint.parameters
        classifications = EndpointClassifier.classify(endpoint, params)
        class_values = {c.value for c in classifications}

        reasons: List[str] = []
        indicators: List[str] = []

        # 1. Static Asset Handling (Deprioritized)
        if EndpointClassification.STATIC_ASSET.value in class_values:
            reasons.append("Static web asset without dynamic server-side logic")
            indicators.append("static_asset")
            return EndpointPriority(
                score=10,
                priority_level=PriorityLevel.LOW,
                reasons=reasons,
                indicators=indicators,
            )

        # Base score for active web endpoints
        score = 30
        reasons.append("Baseline interactive web resource")

        # 2. Authentication Boundary
        if EndpointClassification.AUTHENTICATION.value in class_values:
            score += 25
            reasons.append("Authentication or session management boundary")
            indicators.append("auth_boundary")

        # 3. Administrative Interface
        if EndpointClassification.ADMIN_LIKE_PATH.value in class_values:
            score += 25
            reasons.append("Administrative or privileged control interface")
            indicators.append("admin_path")

        # 4. File Upload / Handling
        if EndpointClassification.FILE_UPLOAD_CANDIDATE.value in class_values:
            score += 20
            reasons.append("File upload or document handling functionality")
            indicators.append("file_upload")

        # 5. State-Changing HTTP Method
        if EndpointClassification.STATE_CHANGING.value in class_values:
            score += 15
            reasons.append(f"State-changing HTTP method ({endpoint.method})")
            indicators.append("state_changing")

        # 6. API Endpoint
        if EndpointClassification.API.value in class_values:
            score += 15
            reasons.append("API route processing structured data")
            indicators.append("api_route")

        # 7. Identifier Endpoint (ID in path or params)
        if EndpointClassification.IDENTIFIER_ENDPOINT.value in class_values:
            score += 15
            reasons.append("Contains resource or user entity identifier")
            indicators.append("identifier_param")

        # 8. Redirect Candidate
        if EndpointClassification.REDIRECT_CANDIDATE.value in class_values:
            score += 15
            reasons.append("Contains URL input or external redirect parameter")
            indicators.append("redirect_param")

        # 9. Search / Query Parameter
        if EndpointClassification.SEARCH.value in class_values:
            score += 10
            reasons.append("Dynamic user query or search input")
            indicators.append("search_query")

        # 10. Parameter Count Influence
        if len(params) >= 3:
            score += 10
            reasons.append(f"Multiple input parameters ({len(params)} parameters)")
            indicators.append("param_density_high")
        elif len(params) >= 1:
            score += 5
            reasons.append(f"Contains {len(params)} input parameter(s)")
            indicators.append("param_density_medium")

        # Clamp score to [0, 100]
        final_score = max(0, min(100, score))

        # Assign categorical priority level
        if final_score >= 80:
            level = PriorityLevel.CRITICAL
        elif final_score >= 60:
            level = PriorityLevel.HIGH
        elif final_score >= 40:
            level = PriorityLevel.MEDIUM
        else:
            level = PriorityLevel.LOW

        return EndpointPriority(
            score=final_score,
            priority_level=level,
            reasons=reasons,
            indicators=indicators,
        )
