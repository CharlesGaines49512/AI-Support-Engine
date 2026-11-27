from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.extractor import EvidenceExtractor
from app.logs.ingestion_contracts import LogIngestionResult
from app.logs.normalizer import LogNormalizer
from app.logs.sanitizer import LogSanitizer
from app.models.incident import Incident
from app.models.log_enums import LogFormat
from app.parsers.exceptions import (
    InvalidLogPayloadError,
    LogResourceLimitError,
)
from app.repositories.application_log import ApplicationLogRepository


class LogIngestionService:
    """Process and persist sanitized application log submissions."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._normalizer = LogNormalizer(settings)
        self._sanitizer = LogSanitizer(settings)
        self._extractor = EvidenceExtractor(settings)

    def ingest(
        self,
        incident_id: UUID,
        payload: bytes,
        source_format: LogFormat,
        *,
        source_name: str | None = None,
    ) -> LogIngestionResult:
        """Process a submission and commit its sanitized records."""

        if not isinstance(payload, bytes):
            raise InvalidLogPayloadError("Application log payload must be bytes.")

        if source_name is not None and not isinstance(source_name, str):
            raise InvalidLogPayloadError("Log source name must be text.")

        if not isinstance(source_format, LogFormat):
            raise InvalidLogPayloadError("Unsupported application log format.")

        if (
            source_name is not None
            and len(source_name) > self._settings.log_max_metadata_chars
        ):
            raise LogResourceLimitError(
                "Log source name exceeds the configured length limit."
            )

        normalized = self._normalizer.parse_and_normalize(
            payload,
            source_format,
        )

        sanitized = self._sanitizer.sanitize(normalized)

        sanitized_source, source_redaction_count = self._sanitizer.sanitize_source_name(
            source_name
        )

        evidence = self._extractor.extract(sanitized)

        with self._session_factory() as session:
            with session.begin():
                incident = session.get(
                    Incident,
                    incident_id,
                    with_for_update=True,
                    populate_existing=True,
                )

                if incident is None:
                    raise IncidentNotFoundError(incident_id)

                repository = ApplicationLogRepository(session)

                submission = repository.create(
                    incident_id,
                    sanitized,
                    source_name=sanitized_source,
                    source_redaction_count=source_redaction_count,
                )

                result = LogIngestionResult(
                    submission_id=submission.id,
                    incident_id=submission.incident_id,
                    source_format=submission.source_format,
                    source_name=submission.source_name,
                    payload_bytes=submission.payload_bytes,
                    entry_count=submission.entry_count,
                    redaction_count=submission.redaction_count,
                    created_at=submission.created_at,
                    evidence=evidence,
                )

        return result
