from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.models.application_log import LogEntry, LogSubmission
from app.models.log_enums import LogFormat, LogSeverity

MAX_PERSISTENCE_PAYLOAD_BYTES = 10_485_760
MAX_PERSISTENCE_ENTRIES = 10_000
MAX_PERSISTENCE_INTEGER = 2**31 - 1
MAX_PERSISTENCE_METADATA_CHARS = 2_000
MAX_PERSISTENCE_MESSAGE_CHARS = 20_000


class ApplicationLogRepository:
    """Persist and retrieve incident-scoped application logs."""

    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _validate_persistence_text(
        value: str | None,
        limit: int,
    ) -> None:
        """Reject unsafe content before database persistence."""
        if value is None:
            return

        if not isinstance(value, str):
            raise ValueError("Log persistence requires safe sanitized content.")

        try:
            validate_outbound_text(value, limit)
        except UnsafeOutboundEvidenceError:
            raise ValueError(
                "Log persistence requires safe sanitized content."
            ) from None

    @classmethod
    def _validate_persistence_entry(
        cls,
        entry: SanitizedLogEntry,
        position: int,
    ) -> None:
        """Validate a complete sanitized event before persistence."""
        if not isinstance(entry, SanitizedLogEntry):
            raise ValueError("Log persistence requires sanitized entries.")

        if type(entry.position) is not int or entry.position != position:
            raise ValueError("Log entry positions must be sequential.")

        if not isinstance(entry.severity, LogSeverity):
            raise ValueError("Log persistence requires a valid severity.")

        if (
            type(entry.redaction_count) is not int
            or not 0 <= entry.redaction_count <= MAX_PERSISTENCE_INTEGER
        ):
            raise ValueError("Entry redaction count cannot be negative.")

        timestamp = entry.event_timestamp

        if timestamp is not None:
            if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
                raise ValueError("Log entry requires a timezone-aware timestamp.")

            try:
                utc_offset = timestamp.utcoffset()

                if utc_offset is None:
                    raise ValueError("Log entry requires a timezone-aware timestamp.")

                timestamp.replace(tzinfo=None) - utc_offset

            except TypeError, ValueError, OverflowError:
                raise ValueError(
                    "Log entry requires a timezone-aware timestamp."
                ) from None

        fields = (
            (entry.message, MAX_PERSISTENCE_MESSAGE_CHARS),
            (entry.original_severity, MAX_PERSISTENCE_METADATA_CHARS),
            (entry.service_name, MAX_PERSISTENCE_METADATA_CHARS),
            (entry.exception, MAX_PERSISTENCE_MESSAGE_CHARS),
            (entry.error_code, MAX_PERSISTENCE_METADATA_CHARS),
            (entry.correlation_id, MAX_PERSISTENCE_METADATA_CHARS),
        )

        for value, limit in fields:
            cls._validate_persistence_text(value, limit)

        if entry.message is None or not entry.message.strip():
            raise ValueError("Log entry requires a nonempty message.")

    def create(
        self,
        incident_id: UUID,
        log: SanitizedLog,
        *,
        source_name: str | None = None,
        source_redaction_count: int = 0,
    ) -> LogSubmission:
        """Persist sanitized records within the caller's transaction."""

        if not isinstance(log, SanitizedLog):
            raise TypeError("Log persistence requires sanitized records.")

        if not isinstance(incident_id, UUID):
            raise ValueError("Log persistence requires a valid incident identifier.")

        if not isinstance(log.source_format, LogFormat):
            raise ValueError("Log persistence requires a valid source format.")

        if (
            type(log.payload_bytes) is not int
            or not 1 <= log.payload_bytes <= MAX_PERSISTENCE_PAYLOAD_BYTES
        ):
            raise ValueError("Log submission requires a positive size and entry count.")

        if (
            type(log.entries) is not tuple
            or not 1 <= log.entry_count <= MAX_PERSISTENCE_ENTRIES
        ):
            raise ValueError("Log submission requires a positive size and entry count.")

        if (
            type(source_redaction_count) is not int
            or not 0 <= source_redaction_count <= MAX_PERSISTENCE_INTEGER
        ):
            raise ValueError("Source redaction count cannot be negative.")

        self._validate_persistence_text(
            source_name,
            MAX_PERSISTENCE_METADATA_CHARS,
        )

        for position, entry in enumerate(log.entries, start=1):
            self._validate_persistence_entry(entry, position)

        if log.redaction_count + source_redaction_count > MAX_PERSISTENCE_INTEGER:
            raise ValueError("Combined redaction count exceeds its storage limit.")

        submission = LogSubmission(
            incident_id=incident_id,
            source_format=log.source_format,
            source_name=source_name,
            payload_bytes=log.payload_bytes,
            entry_count=log.entry_count,
            redaction_count=(log.redaction_count + source_redaction_count),
        )

        self._session.add(submission)
        self._session.flush()

        entries = [
            LogEntry(
                submission_id=submission.id,
                position=entry.position,
                event_timestamp=entry.event_timestamp,
                severity=entry.severity,
                original_severity=entry.original_severity,
                service_name=entry.service_name,
                message=entry.message,
                exception=entry.exception,
                error_code=entry.error_code,
                correlation_id=entry.correlation_id,
            )
            for entry in log.entries
        ]

        self._session.add_all(entries)
        self._session.flush()
        self._session.refresh(submission)

        return submission

    def get_by_id(
        self,
        incident_id: UUID,
        submission_id: UUID,
    ) -> LogSubmission | None:
        statement = select(LogSubmission).where(
            LogSubmission.incident_id == incident_id,
            LogSubmission.id == submission_id,
        )

        return self._session.scalars(statement).one_or_none()

    def list_by_incident(
        self,
        incident_id: UUID,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> list[LogSubmission]:
        statement = (
            select(LogSubmission)
            .where(LogSubmission.incident_id == incident_id)
            .order_by(
                LogSubmission.created_at.desc(),
                LogSubmission.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        )

        return list(self._session.scalars(statement).all())

    def count_by_incident(
        self,
        incident_id: UUID,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(LogSubmission)
            .where(LogSubmission.incident_id == incident_id)
        )

        return self._session.execute(statement).scalar_one()

    def get_entry(
        self,
        incident_id: UUID,
        submission_id: UUID,
        entry_id: UUID,
    ) -> LogEntry | None:
        statement = (
            select(LogEntry)
            .join(
                LogSubmission,
                LogEntry.submission_id == LogSubmission.id,
            )
            .where(
                LogSubmission.incident_id == incident_id,
                LogSubmission.id == submission_id,
                LogEntry.id == entry_id,
            )
        )

        return self._session.scalars(statement).one_or_none()

    def list_entries(
        self,
        incident_id: UUID,
        submission_id: UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        severity: LogSeverity | None = None,
    ) -> list[LogEntry]:
        statement = (
            select(LogEntry)
            .join(
                LogSubmission,
                LogEntry.submission_id == LogSubmission.id,
            )
            .where(
                LogSubmission.incident_id == incident_id,
                LogSubmission.id == submission_id,
            )
        )

        if severity is not None:
            statement = statement.where(LogEntry.severity == severity)

        statement = (
            statement.order_by(LogEntry.position.asc()).offset(offset).limit(limit)
        )

        return list(self._session.scalars(statement).all())

    def count_entries(
        self,
        incident_id: UUID,
        submission_id: UUID,
        *,
        severity: LogSeverity | None = None,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(LogEntry)
            .join(
                LogSubmission,
                LogEntry.submission_id == LogSubmission.id,
            )
            .where(
                LogSubmission.incident_id == incident_id,
                LogSubmission.id == submission_id,
            )
        )

        if severity is not None:
            statement = statement.where(LogEntry.severity == severity)

        return self._session.execute(statement).scalar_one()

    def delete(
        self,
        incident_id: UUID,
        submission_id: UUID,
    ) -> bool:
        submission = self.get_by_id(
            incident_id,
            submission_id,
        )

        if submission is None:
            return False

        self._session.delete(submission)
        self._session.flush()

        return True
