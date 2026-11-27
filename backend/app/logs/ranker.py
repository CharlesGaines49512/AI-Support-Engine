from collections import defaultdict
from types import MappingProxyType

from app.logs.evidence_contracts import (
    DiagnosticCategory,
    DiagnosticFinding,
    DiagnosticReport,
)
from app.logs.ranking_contracts import (
    RankedDiagnosticReport,
    RankedFinding,
)
from app.models.log_enums import LogSeverity

SEVERITY_SCORES = MappingProxyType(
    {
        LogSeverity.TRACE: 0,
        LogSeverity.DEBUG: 2,
        LogSeverity.INFO: 5,
        LogSeverity.WARNING: 20,
        LogSeverity.ERROR: 40,
        LogSeverity.CRITICAL: 60,
        LogSeverity.UNKNOWN: 10,
    }
)

CATEGORY_SCORES = MappingProxyType(
    {
        DiagnosticCategory.SECURITY: 10,
        DiagnosticCategory.INFRASTRUCTURE: 5,
    }
)

SPECIFICITY_SCORE = 25
RECURRENCE_POINTS = 3
MAX_RECURRENCE_SCORE = 15
MAX_FINDING_SCORE = 110


class DiagnosticRanker:
    """Rank diagnostic findings using deterministic heuristics."""

    @staticmethod
    def _score_finding(
        finding: DiagnosticFinding,
        occurrence_count: int,
    ) -> RankedFinding:
        severity_score = SEVERITY_SCORES[finding.severity]

        specificity_score = (
            0 if finding.category == DiagnosticCategory.GENERAL else SPECIFICITY_SCORE
        )

        category_score = CATEGORY_SCORES.get(
            finding.category,
            0,
        )

        recurrence_score = min(
            (occurrence_count - 1) * RECURRENCE_POINTS,
            MAX_RECURRENCE_SCORE,
        )

        score = severity_score + specificity_score + category_score + recurrence_score

        return RankedFinding(
            finding=finding,
            score=score,
            severity_score=severity_score,
            specificity_score=specificity_score,
            category_score=category_score,
            recurrence_score=recurrence_score,
            occurrence_count=occurrence_count,
        )

    def rank(
        self,
        report: DiagnosticReport,
    ) -> RankedDiagnosticReport:
        """Rank findings while preserving their event references."""

        if report.entry_count < 0:
            raise ValueError("Diagnostic entry count cannot be negative.")

        occurrences: dict[str, set[int]] = defaultdict(set)
        seen: set[tuple[int, str]] = set()

        for finding in report.findings:
            if not 1 <= finding.position <= report.entry_count:
                raise ValueError("Diagnostic finding has an invalid event position.")

            identifier = (
                finding.position,
                finding.rule_id,
            )

            if identifier in seen:
                raise ValueError("Diagnostic report contains duplicate findings.")

            seen.add(identifier)

            occurrences[finding.rule_id].add(finding.position)

        ranked = [
            self._score_finding(
                finding,
                len(occurrences[finding.rule_id]),
            )
            for finding in report.findings
        ]

        ranked.sort(
            key=lambda item: (
                -item.score,
                -item.severity_score,
                item.finding.position,
                item.finding.rule_id,
            )
        )

        return RankedDiagnosticReport(
            entry_count=report.entry_count,
            findings=tuple(ranked),
        )
