from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from app.models.application_log import LogEntry, LogSubmission
from app.models.log_enums import LogFormat, LogSeverity


@dataclass(frozen=True, slots=True)
class LogSubmissionRecord:
    id: UUID
    incident_id: UUID
    source_format: LogFormat
    source_name: str | None = field(repr=False)
    payload_bytes: int
    entry_count: int
    redaction_count: int
    created_at: datetime

    @classmethod
    def from_model(
        cls,
        submission: LogSubmission,
    ) -> LogSubmissionRecord:
        return cls(
            id=submission.id,
            incident_id=submission.incident_id,
            source_format=submission.source_format,
            source_name=submission.source_name,
            payload_bytes=submission.payload_bytes,
            entry_count=submission.entry_count,
            redaction_count=submission.redaction_count,
            created_at=submission.created_at,
        )


@dataclass(frozen=True, slots=True)
class LogEntryRecord:
    id: UUID
    submission_id: UUID
    position: int
    severity: LogSeverity
    message: str = field(repr=False)
    event_timestamp: datetime | None = None
    original_severity: str | None = field(default=None, repr=False)
    service_name: str | None = field(default=None, repr=False)
    exception: str | None = field(default=None, repr=False)
    error_code: str | None = field(default=None, repr=False)
    correlation_id: str | None = field(default=None, repr=False)

    @classmethod
    def from_model(
        cls,
        entry: LogEntry,
    ) -> LogEntryRecord:
        return cls(
            id=entry.id,
            submission_id=entry.submission_id,
            position=entry.position,
            severity=entry.severity,
            message=entry.message,
            event_timestamp=entry.event_timestamp,
            original_severity=entry.original_severity,
            service_name=entry.service_name,
            exception=entry.exception,
            error_code=entry.error_code,
            correlation_id=entry.correlation_id,
        )


@dataclass(frozen=True, slots=True)
class LogPage[T]:
    items: tuple[T, ...]
    total: int
    offset: int
    limit: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total
