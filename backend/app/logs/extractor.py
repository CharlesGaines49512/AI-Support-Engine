from dataclasses import replace

from app.core.config import Settings
from app.logs.detector import DiagnosticDetector
from app.logs.evidence_contracts import DiagnosticCategory
from app.logs.extraction_contracts import (
    EvidenceEvent,
    EvidencePackage,
)
from app.logs.ranker import DiagnosticRanker
from app.logs.ranking_contracts import RankedFinding
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.parsers.validation import validate_entry_count


class EvidenceExtractor:
    """Select bounded evidence from sanitized diagnostic events."""

    def __init__(
        self,
        settings: Settings,
    ) -> None:
        self._settings = settings
        self._detector = DiagnosticDetector()
        self._ranker = DiagnosticRanker()

    @staticmethod
    def _make_event(
        entry: SanitizedLogEntry,
        findings: list[RankedFinding],
    ) -> EvidenceEvent:
        categories = tuple(
            sorted({ranked.finding.category.value for ranked in findings})
        )

        return EvidenceEvent(
            position=entry.position,
            severity=entry.severity,
            score=max(ranked.score for ranked in findings),
            rule_ids=tuple(ranked.finding.rule_id for ranked in findings),
            categories=categories,
            message=entry.message,
            exception=entry.exception,
            error_code=entry.error_code,
            service_name=entry.service_name,
            event_timestamp=(
                entry.event_timestamp.isoformat()
                if entry.event_timestamp is not None
                else None
            ),
        )

    @staticmethod
    def _metadata_only(
        event: EvidenceEvent,
    ) -> EvidenceEvent:
        return replace(
            event,
            details_omitted=True,
            message=None,
            exception=None,
            error_code=None,
            service_name=None,
            event_timestamp=None,
        )

    def _try_add(
        self,
        package: EvidencePackage,
        event: EvidenceEvent,
    ) -> EvidencePackage | None:
        limit = self._settings.log_max_evidence_chars

        proposed = replace(
            package,
            events=(*package.events, event),
        )

        if proposed.character_count <= limit:
            return proposed

        reduced = self._metadata_only(event)

        proposed = replace(
            package,
            events=(*package.events, reduced),
        )

        if proposed.character_count <= limit:
            return proposed

        return None

    def extract(
        self,
        log: SanitizedLog,
    ) -> EvidencePackage:
        """Detect, rank and select evidence within configured limits."""

        if not isinstance(log, SanitizedLog):
            raise TypeError("Evidence extraction requires sanitized logs.")

        validate_entry_count(
            log.entry_count,
            self._settings,
        )

        for position, entry in enumerate(
            log.entries,
            start=1,
        ):
            if entry.position != position:
                raise ValueError("Evidence requires sequential event positions.")

        diagnostics = self._detector.detect(log)
        ranked = self._ranker.rank(diagnostics)

        grouped: dict[int, list[RankedFinding]] = {}

        for finding in ranked.findings:
            position = finding.finding.position

            grouped.setdefault(position, []).append(finding)

        candidates = [
            self._make_event(
                log.entries[position - 1],
                findings,
            )
            for position, findings in grouped.items()
        ]

        package = EvidencePackage(
            source_format=log.source_format,
            total_events=log.entry_count,
            diagnostic_events=len(candidates),
            events=(),
        )

        if package.character_count > self._settings.log_max_evidence_chars:
            raise ValueError("Evidence budget cannot contain package metadata.")

        covered_categories: set[str] = set()
        attempted_positions: set[int] = set()

        for diverse_only in (True, False):
            for candidate in candidates:
                if (
                    package.selected_event_count
                    >= self._settings.log_max_evidence_entries
                ):
                    return package

                if candidate.position in attempted_positions:
                    continue

                categories = set(candidate.categories) - {
                    DiagnosticCategory.GENERAL.value
                }

                if (
                    diverse_only
                    and package.has_evidence
                    and not categories.difference(covered_categories)
                ):
                    continue

                attempted_positions.add(candidate.position)

                proposed = self._try_add(
                    package,
                    candidate,
                )

                if proposed is None:
                    continue

                package = proposed

                covered_categories.update(categories)

        return package
