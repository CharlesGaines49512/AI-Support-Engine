import json
from dataclasses import dataclass, field
from uuid import UUID

from app.core.config import Settings
from app.logs.extraction_contracts import EvidencePackage
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_event,
)

LOG_EVIDENCE_VERSION = "1.0.0"


class InvalidLogEvidenceError(ValueError):
    """Diagnostic evidence cannot be used for AI analysis."""


@dataclass(frozen=True, slots=True)
class AIAnalysisLogContext:
    """Untrusted diagnostic evidence associated with an incident."""

    incident_id: UUID
    submission_id: UUID
    evidence: EvidencePackage = field(repr=False)

    @property
    def has_evidence(self) -> bool:
        return self.evidence.has_evidence

    @property
    def selected_event_count(self) -> int:
        return self.evidence.selected_event_count

    @property
    def evidence_character_count(self) -> int:
        return self.evidence.character_count

    def validate(
        self,
        settings: Settings,
        incident_id: UUID,
    ) -> None:
        if self.incident_id != incident_id:
            raise InvalidLogEvidenceError(
                "Diagnostic evidence belongs to another incident."
            )

        if not isinstance(self.submission_id, UUID):
            raise InvalidLogEvidenceError("Invalid diagnostic submission identifier.")

        evidence = self.evidence

        if evidence.total_events <= 0:
            raise InvalidLogEvidenceError(
                "Diagnostic evidence requires a valid event count."
            )

        if evidence.total_events > settings.log_max_entries:
            raise InvalidLogEvidenceError(
                "Diagnostic evidence exceeds the log entry limit."
            )

        if not (0 <= evidence.diagnostic_events <= evidence.total_events):
            raise InvalidLogEvidenceError("Invalid diagnostic event accounting.")

        if not (0 <= evidence.selected_event_count <= evidence.diagnostic_events):
            raise InvalidLogEvidenceError("Invalid selected event accounting.")

        if evidence.selected_event_count > settings.log_max_evidence_entries:
            raise InvalidLogEvidenceError(
                "Diagnostic evidence exceeds the evidence entry limit."
            )

        if evidence.character_count > settings.log_max_evidence_chars:
            raise InvalidLogEvidenceError(
                "Diagnostic evidence exceeds the character limit."
            )

        positions: set[int] = set()

        for event in evidence.events:
            if (
                type(event.position) is not int
                or not 1 <= event.position <= evidence.total_events
                or event.position in positions
            ):
                raise InvalidLogEvidenceError("Invalid diagnostic event reference.")

            positions.add(event.position)

            if type(event.score) is not int or not 0 <= event.score <= 110:
                raise InvalidLogEvidenceError("Invalid diagnostic relevance score.")

            if not event.rule_ids or not event.categories:
                raise InvalidLogEvidenceError(
                    "Diagnostic event is missing rule references."
                )

            try:
                validate_outbound_event(event, settings)
            except UnsafeOutboundEvidenceError as error:
                raise InvalidLogEvidenceError(str(error)) from None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": LOG_EVIDENCE_VERSION,
            "incident_id": str(self.incident_id),
            "submission_id": str(self.submission_id),
            "trust_level": "untrusted",
            "evidence_type": "diagnostic_indicators",
            "evidence": json.loads(self.evidence.to_json()),
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
        )

    @property
    def character_count(self) -> int:
        return len(self.to_json())
