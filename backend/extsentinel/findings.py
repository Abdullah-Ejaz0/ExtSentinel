"""Collects findings and merges repeats of the same rule into one entry."""

from __future__ import annotations

from .models import Category, Confidence, Evidence, Finding, Severity

MAX_EVIDENCE_PER_FINDING = 8
_CONFIDENCE_RANK = {Confidence.POSSIBLE: 0, Confidence.LIKELY: 1, Confidence.CONFIRMED: 2}


class FindingCollector:
    """Merges findings with the same (rule_id, title) so the user sees one reason per behaviour."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], Finding] = {}

    def add(
        self,
        rule_id: str,
        category: Category,
        severity: Severity,
        title: str,
        description: str,
        evidence: Evidence | list[Evidence] | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        tags: list[str] | None = None,
    ) -> Finding:
        items = [] if evidence is None else ([evidence] if isinstance(evidence, Evidence) else list(evidence))
        key = (rule_id, title)
        existing = self._by_key.get(key)
        if existing is None:
            finding = Finding(
                rule_id=rule_id,
                category=category,
                severity=severity,
                confidence=confidence,
                title=title,
                description=description,
                evidence=items[:MAX_EVIDENCE_PER_FINDING],
                occurrences=1,
                tags=sorted(set(tags or [])),
            )
            self._by_key[key] = finding
            return finding
        if severity.rank > existing.severity.rank:
            existing.severity = severity
        if _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[existing.confidence]:
            existing.confidence = confidence
        for ev in items:
            if len(existing.evidence) < MAX_EVIDENCE_PER_FINDING and ev not in existing.evidence:
                existing.evidence.append(ev)
        existing.tags = sorted(set(existing.tags) | set(tags or []))
        existing.occurrences += 1
        return existing

    def add_finding(self, f: Finding) -> None:
        self.add(f.rule_id, f.category, f.severity, f.title, f.description, f.evidence, f.confidence, f.tags)

    def results(self) -> list[Finding]:
        return sorted(
            self._by_key.values(),
            key=lambda f: (-f.severity.rank, -_CONFIDENCE_RANK[f.confidence], f.category.value, f.rule_id),
        )
