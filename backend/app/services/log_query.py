from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.exceptions import (
    InvalidLogPaginationError,
    LogEntryNotFoundError,
    LogPersistenceIntegrityError,
    LogSubmissionNotFoundError,
)
from app.logs.extraction_contracts import EvidencePackage
from app.logs.extractor import EvidenceExtractor
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.query_contracts import (
    LogEntryRecord,
    LogPage,
    LogSubmissionRecord,
)
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.models.application_log import LogEntry, LogSubmission
from app.models.incident import Incident
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.validation import validate_entry_count
from app.repositories.application_log import (
    MAX_PERSISTENCE_ENTRIES,
    MAX_PERSISTENCE_INTEGER,
    MAX_PERSISTENCE_PAYLOAD_BYTES,
    ApplicationLogRepository,
)

MAX_PAGE_SIZE = 100
MAX_PAGE_OFFSET = 2**63 - 1


class LogQueryService:
    """Retrieve and manage incident-scoped application logs."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        settings: Settings,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._extractor = EvidenceExtractor(settings)

    @staticmethod
    def _validate_pagination(
        offset: int,
        limit: int,
    ) -> None:
        if (
            type(offset) is not int
            or type(limit) is not int
            or not 0 <= offset <= MAX_PAGE_OFFSET
            or not 1 <= limit <= MAX_PAGE_SIZE
        ):
            raise InvalidLogPaginationError()

    @staticmethod
    def _require_incident(
        session: Session,
        incident_id: UUID,
    ) -> None:
        if session.get(Incident, incident_id) is None:
            raise IncidentNotFoundError(incident_id)

    @staticmethod
    def _require_submission(
        repository: ApplicationLogRepository,
        incident_id: UUID,
        submission_id: UUID,
    ) -> LogSubmission:
        submission = repository.get_by_id(
            incident_id,
            submission_id,
        )

        if submission is None:
            raise LogSubmissionNotFoundError()

        if submission.id != submission_id or submission.incident_id != incident_id:
            raise LogPersistenceIntegrityError()

        return submission

    @staticmethod
    def _validate_stored_text(
        value: str | None,
        limit: int,
    ) -> None:
        """Reject unsafe historical content without modifying it."""
        if value is None:
            return

        try:
            validate_outbound_text(value, limit)
        except UnsafeOutboundEvidenceError:
            raise LogPersistenceIntegrityError() from None

    @staticmethod
    def _normalize_stored_timestamp(
        value: object,
    ) -> datetime:
        """Verify and normalize a persisted timestamp."""
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise LogPersistenceIntegrityError()

        try:
            utc_offset = value.utcoffset()

            if utc_offset is None:
                raise LogPersistenceIntegrityError()

            return (value.replace(tzinfo=None) - utc_offset).replace(tzinfo=UTC)

        except TypeError, ValueError, OverflowError:
            raise LogPersistenceIntegrityError() from None

    def _validate_stored_submission(
        self,
        submission: LogSubmission,
    ) -> None:
        """Verify persisted submission metadata."""

        if not isinstance(submission.id, UUID) or not isinstance(
            submission.incident_id, UUID
        ):
            raise LogPersistenceIntegrityError()

        if not isinstance(submission.source_format, LogFormat):
            raise LogPersistenceIntegrityError()

        if (
            type(submission.payload_bytes) is not int
            or not 1 <= submission.payload_bytes <= MAX_PERSISTENCE_PAYLOAD_BYTES
        ):
            raise LogPersistenceIntegrityError()

        if (
            type(submission.entry_count) is not int
            or not 1 <= submission.entry_count <= MAX_PERSISTENCE_ENTRIES
        ):
            raise LogPersistenceIntegrityError()

        if (
            type(submission.redaction_count) is not int
            or not 0 <= submission.redaction_count <= MAX_PERSISTENCE_INTEGER
        ):
            raise LogPersistenceIntegrityError()

        self._normalize_stored_timestamp(submission.created_at)

        self._validate_stored_text(
            submission.source_name,
            self._settings.log_max_metadata_chars,
        )

    def _validate_stored_entry(
        self,
        entry: LogEntry,
    ) -> None:
        """Verify every persisted entry text field."""

        if not isinstance(entry.id, UUID) or not isinstance(entry.submission_id, UUID):
            raise LogPersistenceIntegrityError()

        if (
            type(entry.position) is not int
            or not 1 <= entry.position <= MAX_PERSISTENCE_ENTRIES
        ):
            raise LogPersistenceIntegrityError()

        if not isinstance(entry.severity, LogSeverity):
            raise LogPersistenceIntegrityError()

        if not isinstance(entry.message, str) or not entry.message.strip():
            raise LogPersistenceIntegrityError()

        timestamp = entry.event_timestamp

        if timestamp is not None:
            self._normalize_stored_timestamp(timestamp)

        message_limit = self._settings.log_max_message_chars
        metadata_limit = self._settings.log_max_metadata_chars

        fields = (
            (entry.message, message_limit),
            (entry.exception, message_limit),
            (entry.original_severity, metadata_limit),
            (entry.service_name, metadata_limit),
            (entry.error_code, metadata_limit),
            (entry.correlation_id, metadata_limit),
        )

        for value, limit in fields:
            self._validate_stored_text(value, limit)

    def _validated_submission_record(
        self,
        submission: LogSubmission,
    ) -> LogSubmissionRecord:
        self._validate_stored_submission(submission)
        return LogSubmissionRecord.from_model(submission)

    def _validated_entry_record(
        self,
        entry: LogEntry,
        submission: LogSubmission,
        *,
        entry_id: UUID | None = None,
    ) -> LogEntryRecord:
        self._validate_stored_entry(entry)

        if (
            entry.submission_id != submission.id
            or entry.position > submission.entry_count
            or (entry_id is not None and entry.id != entry_id)
        ):
            raise LogPersistenceIntegrityError()

        return LogEntryRecord.from_model(entry)

    def get_submission(
        self,
        incident_id: UUID,
        submission_id: UUID,
    ) -> LogSubmissionRecord:
        with self._session_factory() as session:
            self._require_incident(session, incident_id)

            repository = ApplicationLogRepository(session)

            submission = self._require_submission(
                repository,
                incident_id,
                submission_id,
            )

            return self._validated_submission_record(submission)

    def list_submissions(
        self,
        incident_id: UUID,
        *,
        offset: int = 0,
        limit: int = 20,
    ) -> LogPage[LogSubmissionRecord]:
        self._validate_pagination(offset, limit)

        with self._session_factory() as session:
            self._require_incident(session, incident_id)

            repository = ApplicationLogRepository(session)

            submissions = repository.list_by_incident(
                incident_id,
                offset=offset,
                limit=limit,
            )

            total = repository.count_by_incident(incident_id)

            for submission in submissions:
                if submission.incident_id != incident_id:
                    raise LogPersistenceIntegrityError()

            return LogPage(
                items=tuple(
                    self._validated_submission_record(submission)
                    for submission in submissions
                ),
                total=total,
                offset=offset,
                limit=limit,
            )

    def get_entry(
        self,
        incident_id: UUID,
        submission_id: UUID,
        entry_id: UUID,
    ) -> LogEntryRecord:
        with self._session_factory() as session:
            self._require_incident(session, incident_id)

            repository = ApplicationLogRepository(session)

            submission = self._require_submission(
                repository,
                incident_id,
                submission_id,
            )
            self._validate_stored_submission(submission)

            entry = repository.get_entry(
                incident_id,
                submission_id,
                entry_id,
            )

            if entry is None:
                raise LogEntryNotFoundError()

            return self._validated_entry_record(
                entry,
                submission,
                entry_id=entry_id,
            )

    def list_entries(
        self,
        incident_id: UUID,
        submission_id: UUID,
        *,
        offset: int = 0,
        limit: int = 20,
        severity: LogSeverity | None = None,
    ) -> LogPage[LogEntryRecord]:
        self._validate_pagination(offset, limit)

        with self._session_factory() as session:
            self._require_incident(session, incident_id)

            repository = ApplicationLogRepository(session)

            submission = self._require_submission(
                repository,
                incident_id,
                submission_id,
            )
            self._validate_stored_submission(submission)

            entries = repository.list_entries(
                incident_id,
                submission_id,
                offset=offset,
                limit=limit,
                severity=severity,
            )

            total = repository.count_entries(
                incident_id,
                submission_id,
                severity=severity,
            )

            return LogPage(
                items=tuple(
                    self._validated_entry_record(entry, submission) for entry in entries
                ),
                total=total,
                offset=offset,
                limit=limit,
            )

    def get_evidence(
        self,
        incident_id: UUID,
        submission_id: UUID,
    ) -> EvidencePackage:
        """Reconstruct evidence from previously sanitized records."""

        with self._session_factory() as session:
            return self.get_evidence_in_session(
                session,
                incident_id,
                submission_id,
            )

    def get_evidence_in_session(
        self,
        session: Session,
        incident_id: UUID,
        submission_id: UUID,
    ) -> EvidencePackage:
        """Reconstruct evidence within the caller's transaction."""

        self._require_incident(session, incident_id)

        repository = ApplicationLogRepository(session)

        submission = self._require_submission(
            repository,
            incident_id,
            submission_id,
        )
        self._validate_stored_submission(submission)

        validate_entry_count(
            submission.entry_count,
            self._settings,
        )

        entries = repository.list_entries(
            incident_id,
            submission_id,
            limit=submission.entry_count + 1,
        )

        if len(entries) != submission.entry_count:
            raise LogPersistenceIntegrityError()

        reconstructed: list[SanitizedLogEntry] = []

        for position, entry in enumerate(
            entries,
            start=1,
        ):
            if entry.position != position:
                raise LogPersistenceIntegrityError()
            self._validate_stored_entry(entry)

            if entry.submission_id != submission.id:
                raise LogPersistenceIntegrityError()

            timestamp = entry.event_timestamp

            if timestamp is not None:
                timestamp = self._normalize_stored_timestamp(timestamp)

            reconstructed.append(
                SanitizedLogEntry(
                    position=entry.position,
                    severity=entry.severity,
                    message=entry.message,
                    event_timestamp=timestamp,
                    original_severity=entry.original_severity,
                    service_name=entry.service_name,
                    exception=entry.exception,
                    error_code=entry.error_code,
                    correlation_id=entry.correlation_id,
                )
            )

        log = SanitizedLog(
            source_format=submission.source_format,
            payload_bytes=submission.payload_bytes,
            entries=tuple(reconstructed),
        )

        return self._extractor.extract(log)

    def delete_submission(
        self,
        incident_id: UUID,
        submission_id: UUID,
    ) -> None:
        with self._session_factory() as session:
            with session.begin():
                self._require_incident(session, incident_id)

                repository = ApplicationLogRepository(session)

                if not repository.delete(
                    incident_id,
                    submission_id,
                ):
                    raise LogSubmissionNotFoundError()
