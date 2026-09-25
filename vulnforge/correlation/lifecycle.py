"""Finding Lifecycle Manager - State transitions, fingerprint tracking, and regression history."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from vulnforge.scanners.result import Finding, FindingStatus


class FindingLifecycleManager:
    """Manages the full finding lifecycle, deterministic state transitions, and scan history alignment."""

    @staticmethod
    def transition_finding(
        finding: Finding,
        new_status: FindingStatus,
        reason: Optional[str] = None,
    ) -> Finding:
        """Explicitly transition a finding to a new verification status."""
        finding.status = new_status
        finding.last_seen = datetime.now(timezone.utc)
        return finding

    def align_lifecycle(
        self,
        current_findings: List[Finding],
        historical_findings: Optional[List[Finding]] = None,
        target_url: Optional[str] = None,
    ) -> List[Finding]:
        """Align finding lifecycle statuses against historical baseline findings.

        Args:
            current_findings: Findings produced during the active scan session.
            historical_findings: Findings from previous scan sessions for comparison.
            target_url: Root target URL being assessed.

        Returns:
            List of current findings enriched with lifecycle timestamps and transition states.
        """
        if not historical_findings:
            # First scan baseline - initialize first_seen and last_seen
            for f in current_findings:
                if target_url:
                    f.target_url = target_url
            return current_findings

        # Build index of historical findings by fingerprint
        hist_map: Dict[str, Finding] = {f.fingerprint: f for f in historical_findings}

        processed: List[Finding] = []
        for curr in current_findings:
            if target_url:
                curr.target_url = target_url

            fp = curr.fingerprint
            if fp in hist_map:
                prev = hist_map[fp]
                # Preserve original discovery timestamp
                curr.first_seen = prev.first_seen
                curr.last_seen = datetime.now(timezone.utc)

                if prev.status == FindingStatus.RESOLVED:
                    # Issue was resolved previously but reappeared
                    curr.status = FindingStatus.REOPENED
                elif prev.status == FindingStatus.FALSE_POSITIVE:
                    curr.status = FindingStatus.FALSE_POSITIVE
                elif prev.status in (FindingStatus.OBSERVED, FindingStatus.POTENTIAL) and curr.confidence >= 70:
                    curr.status = FindingStatus.PROBABLE if curr.confidence < 90 else FindingStatus.CONFIRMED
                elif prev.status in (FindingStatus.PROBABLE, FindingStatus.CONFIRMED):
                    curr.status = FindingStatus.CONFIRMED
            else:
                # Newly observed finding
                curr.first_seen = datetime.now(timezone.utc)
                curr.last_seen = curr.first_seen
                if curr.confidence >= 90:
                    curr.status = FindingStatus.CONFIRMED
                elif curr.confidence >= 70:
                    curr.status = FindingStatus.PROBABLE
                elif curr.confidence >= 40:
                    curr.status = FindingStatus.POTENTIAL
                else:
                    curr.status = FindingStatus.OBSERVED

            processed.append(curr)

        return processed

    def detect_resolved(
        self,
        current_findings: List[Finding],
        historical_findings: List[Finding],
    ) -> List[Finding]:
        """Identify findings present in previous scan but absent in current scan."""
        curr_fingerprints = {f.fingerprint for f in current_findings}
        resolved: List[Finding] = []

        for h in historical_findings:
            if h.fingerprint not in curr_fingerprints and h.status not in (
                FindingStatus.RESOLVED,
                FindingStatus.FALSE_POSITIVE,
            ):
                resolved_copy = h.model_copy(deep=True)
                resolved_copy.status = FindingStatus.RESOLVED
                resolved_copy.last_seen = datetime.now(timezone.utc)
                resolved.append(resolved_copy)

        return resolved
