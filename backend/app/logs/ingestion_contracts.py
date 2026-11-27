from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from app.logs.extraction_contracts import EvidencePackage
from app.models.log_enums import LogFormat


@dataclass(frozen=True, slots=True)
class LogIngestionResult:
    """Committed submission metadata and diagnostic evidence."""

    submission_id: UUID
    incident_id: UUID
    source_format: LogFormat
    source_name: str | None = field(repr=False)
    payload_bytes: int
    entry_count: int
    redaction_count: int
    created_at: datetime
    evidence: EvidencePackage

    @property
    def has_diagnostic_evidence(self) -> bool:
        return self.evidence.has_evidence

    @property
    def was_redacted(self) -> bool:
        return self.redaction_count > 0
