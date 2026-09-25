"""Deduplication and consolidation engine for security findings."""

from typing import Dict, List
from urllib.parse import urlparse

from vulnforge.scanners.result import Finding, FindingSeverity
from vulnforge.utils.redaction import redact_secrets


class FindingDeduplicator:
    """Consolidates and merges duplicate security findings across scanners."""

    SEVERITY_ORDER = {
        FindingSeverity.CRITICAL: 5,
        FindingSeverity.HIGH: 4,
        FindingSeverity.MEDIUM: 3,
        FindingSeverity.LOW: 2,
        FindingSeverity.INFO: 1,
    }

    @classmethod
    def get_canonical_key(cls, finding: Finding) -> str:
        """Generate a canonical comparison key for finding identity."""
        parsed = urlparse(finding.endpoint_url)
        normalized_path = parsed.path.rstrip("/") or "/"
        param = (finding.parameter_name or "").strip().lower()
        cat = finding.category.strip().lower()

        return f"{parsed.netloc}::{normalized_path}::{param}::{cat}"

    @classmethod
    def merge(cls, findings: List[Finding]) -> List[Finding]:
        """Merge duplicate findings on the same endpoint, parameter, and category.

        Args:
            findings: List of raw or candidate Finding objects.

        Returns:
            Deduplicated list of consolidated Finding objects.
        """
        if not findings:
            return []

        grouped: Dict[str, List[Finding]] = {}
        for f in findings:
            key = cls.get_canonical_key(f)
            grouped.setdefault(key, []).append(f)

        consolidated: List[Finding] = []

        for key, group in grouped.items():
            if len(group) == 1:
                single = group[0]
                # Ensure evidence is redacted
                single.evidence = redact_secrets(single.evidence)
                consolidated.append(single)
                continue

            # Merge group into a single consolidated finding
            primary = group[0]

            # 1. Pick maximum severity
            best_sev = max(
                (f.severity for f in group),
                key=lambda s: cls.SEVERITY_ORDER.get(s, 0),
            )

            # 2. Pick maximum confidence
            best_conf = max(f.confidence for f in group)

            # 3. Combine unique evidence snippets
            all_evidence: List[str] = []
            for f in group:
                if f.evidence:
                    redacted = redact_secrets(f.evidence.strip())
                    if redacted and redacted not in all_evidence:
                        all_evidence.append(redacted)
            combined_evidence = "\n---\n".join(all_evidence)

            # 4. Combine unique references
            all_refs: List[str] = []
            for f in group:
                for r in f.references:
                    if r not in all_refs:
                        all_refs.append(r)

            # 5. Combined scanner attribution
            scanners_used = sorted(list({f.scanner for f in group}))
            scanner_attrib = ", ".join(scanners_used)

            merged = Finding(
                id=primary.id,
                scanner=scanner_attrib,
                category=primary.category,
                title=primary.title,
                severity=best_sev,
                confidence=best_conf,
                status=primary.status,
                endpoint_url=primary.endpoint_url,
                parameter_name=primary.parameter_name,
                description=primary.description,
                evidence=combined_evidence,
                recommendation=primary.recommendation,
                references=all_refs,
                created_at=primary.created_at,
            )
            consolidated.append(merged)

        return consolidated
