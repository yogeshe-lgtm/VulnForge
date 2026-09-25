"""Explainable confidence evaluation and scoring engine for security findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from vulnforge.scanners.result import FindingStatus, Observation, ObservationType, ResponseDifference


class ConfidenceLevel(str, Enum):
    """Categorical confidence classification bands."""

    INSUFFICIENT = "Insufficient evidence"  # 0–39%
    POTENTIAL = "Potential"                  # 40–69%
    PROBABLE = "Probable"                    # 70–89%
    HIGH = "High confidence"                 # 90–100%

    @classmethod
    def from_score(cls, score: int) -> "ConfidenceLevel":
        """Map a numeric 0-100 score to its confidence band."""
        if score >= 90:
            return cls.HIGH
        elif score >= 70:
            return cls.PROBABLE
        elif score >= 40:
            return cls.POTENTIAL
        return cls.INSUFFICIENT


@dataclass
class ConfidenceSignal:
    """Represents an atomic positive or negative confidence signal with rationale."""

    name: str
    weight: int  # Positive for supporting evidence, negative for dampening/noise
    description: str
    passed: bool = True

    @property
    def display_text(self) -> str:
        """Formatted bullet string for CLI and report presentation."""
        icon = "✓" if self.passed and self.weight >= 0 else "✗" if not self.passed else "!"
        return f"{icon} {self.description}"


@dataclass
class ConfidenceReport:
    """Complete explainable confidence breakdown for a security finding."""

    score: int  # 0 to 100
    level: ConfidenceLevel
    signals: List[ConfidenceSignal] = field(default_factory=list)

    @property
    def signal_explanations(self) -> List[str]:
        """List of human-readable signal explanation strings."""
        return [s.display_text for s in self.signals if s.passed]


class ConfidenceEngine:
    """Evaluates multi-source observations and response deltas to compute an explainable score."""

    @classmethod
    def evaluate(
        cls,
        base_score: int = 50,
        observations: Optional[List[Observation]] = None,
        response_diff: Optional[ResponseDifference] = None,
        custom_signals: Optional[List[ConfidenceSignal]] = None,
    ) -> ConfidenceReport:
        """Calculate explainable confidence score from observed telemetry and diffs.

        Args:
            base_score: Starting baseline confidence.
            observations: List of correlated observations.
            response_diff: Structural response difference from baseline.
            custom_signals: Explicit signals provided by scanners.

        Returns:
            ConfidenceReport containing numeric score, level, and signal breakdown.
        """
        score = base_score
        signals: List[ConfidenceSignal] = []

        if custom_signals:
            for sig in custom_signals:
                signals.append(sig)
                if sig.passed:
                    score += sig.weight

        obs_list = observations or []
        obs_types = {o.observation_type for o in obs_list}

        # 1. Input reflection signal
        if ObservationType.REFLECTION in obs_types:
            sig = ConfidenceSignal(
                name="input_reflection",
                weight=20,
                description="Input reflected in server response body",
                passed=True,
            )
            signals.append(sig)
            score += sig.weight

        # 2. Dangerous execution context / Error pattern
        if ObservationType.ERROR_PATTERN in obs_types:
            sig = ConfidenceSignal(
                name="error_pattern_disclosure",
                weight=15,
                description="Database or runtime syntax error disclosed",
                passed=True,
            )
            signals.append(sig)
            score += sig.weight

        # 3. Response difference analysis
        if response_diff:
            if response_diff.status_changed:
                sig = ConfidenceSignal(
                    name="status_divergence",
                    weight=10,
                    description=f"HTTP status changed from {response_diff.status_baseline} to {response_diff.status_candidate}",
                    passed=True,
                )
                signals.append(sig)
                score += sig.weight

            if response_diff.content_changed and response_diff.similarity_ratio < 0.8:
                sig = ConfidenceSignal(
                    name="structural_divergence",
                    weight=15,
                    description=f"Response body structurally altered (similarity: {int(response_diff.similarity_ratio * 100)}%)",
                    passed=True,
                )
                signals.append(sig)
                score += sig.weight

            if response_diff.timing_changed:
                sig = ConfidenceSignal(
                    name="timing_divergence",
                    weight=15,
                    description=f"Significant response time divergence ({response_diff.timing_delta_seconds:+.2f}s)",
                    passed=True,
                )
                signals.append(sig)
                score += sig.weight

        # 4. Multi-observation confirmation
        if len(obs_list) >= 3:
            sig = ConfidenceSignal(
                name="multi_signal_corroboration",
                weight=10,
                description=f"Corroborated across {len(obs_list)} distinct telemetry observations",
                passed=True,
            )
            signals.append(sig)
            score += sig.weight

        # Clamp between 0 and 100
        clamped_score = max(0, min(100, score))
        level = ConfidenceLevel.from_score(clamped_score)

        return ConfidenceReport(
            score=clamped_score,
            level=level,
            signals=signals,
        )

    @classmethod
    def determine_finding_status(cls, confidence_score: int) -> FindingStatus:
        """Map confidence score to appropriate FindingStatus."""
        if confidence_score >= 90:
            return FindingStatus.CONFIRMED
        elif confidence_score >= 70:
            return FindingStatus.POTENTIAL
        elif confidence_score >= 40:
            return FindingStatus.REQUIRES_MANUAL_VERIFICATION
        return FindingStatus.OBSERVED
