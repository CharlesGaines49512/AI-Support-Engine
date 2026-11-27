import json
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.ingestion_contracts import LogIngestionResult
from app.logs.sanitized_contracts import SanitizedLog
from app.models.application_log import LogEntry, LogSubmission
from app.models.incident import Incident
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.repositories.application_log import ApplicationLogRepository
from app.services.log_ingestion import LogIngestionService

CANARY = "SYNTHETIC_SECRET_CANARY"


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 8192,
            "log_max_entries": 10,
            "log_max_message_chars": 1000,
            "log_max_metadata_chars": 200,
            "log_max_evidence_entries": 5,
            "log_max_evidence_chars": 2048,
        }
    )


@pytest.fixture
def session_factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=integration_engine,
        autoflush=False,
        expire_on_commit=True,
    )


@pytest.fixture
def service(
    session_factory: sessionmaker[Session],
    settings: Settings,
) -> LogIngestionService:
    return LogIngestionService(
        session_factory,
        settings,
    )


@pytest.fixture
def incident_id(
    session_factory: sessionmaker[Session],
) -> Iterator[UUID]:
    identifier = uuid4()

    try:
        with session_factory.begin() as session:
            session.add(
                Incident(
                    id=identifier,
                    title="log-ingestion-service-test",
                    description="Synthetic ingestion test.",
                )
            )

        yield identifier

    finally:
        with session_factory.begin() as session:
            session.execute(delete(Incident).where(Incident.id == identifier))


def submission_count(
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> int:
    with session_factory() as session:
        statement = (
            select(func.count())
            .select_from(LogSubmission)
            .where(LogSubmission.incident_id == incident_id)
        )

        return session.execute(statement).scalar_one()


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<event severity="ERROR" message="Database connection failed"/>',
        ),
        (
            LogFormat.JSON,
            b'{"severity":"ERROR","message":"Database connection failed"}',
        ),
        (
            LogFormat.TEXT,
            b"ERROR Database connection failed",
        ),
    ],
)
def test_ingest_all_supported_formats(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    result = service.ingest(
        incident_id,
        payload,
        source_format,
        source_name="database-service",
    )

    assert isinstance(result, LogIngestionResult)
    assert result.incident_id == incident_id
    assert result.source_format == source_format
    assert result.source_name == "database-service"
    assert result.payload_bytes == len(payload)
    assert result.entry_count == 1
    assert result.redaction_count == 0
    assert result.was_redacted is False
    assert result.has_diagnostic_evidence is True
    assert result.created_at.tzinfo is not None

    assert result.evidence.events[0].rule_ids == (
        "DB-002",
        "SEV-001",
    )

    with session_factory() as session:
        repository = ApplicationLogRepository(session)

        stored = repository.get_by_id(
            incident_id,
            result.submission_id,
        )

        assert stored is not None
        assert stored.source_format == source_format
        assert stored.source_name == result.source_name
        assert stored.payload_bytes == len(payload)
        assert stored.entry_count == 1
        assert stored.redaction_count == 0
        assert stored.created_at == result.created_at

        entries = repository.list_entries(
            incident_id,
            result.submission_id,
        )

        assert len(entries) == 1
        assert entries[0].position == 1
        assert entries[0].severity == LogSeverity.ERROR
        assert entries[0].message == "Database connection failed"


def test_credentials_redacted_before_persistence(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    document = {
        "severity": "ERROR",
        "message": f"Authentication failed password={CANARY}",
        "exception": f"password={CANARY}",
        "service_name": f"password={CANARY}",
        "error_code": f"password={CANARY}",
        "correlation_id": f"password={CANARY}",
    }

    result = service.ingest(
        incident_id,
        json.dumps(document).encode("utf-8"),
        LogFormat.JSON,
        source_name=f"password={CANARY}",
    )

    assert result.was_redacted is True
    assert result.redaction_count > 0
    assert result.source_name is not None
    assert CANARY not in result.source_name
    assert CANARY not in result.evidence.to_json()
    assert CANARY not in repr(result)

    with session_factory() as session:
        repository = ApplicationLogRepository(session)

        stored = repository.get_by_id(
            incident_id,
            result.submission_id,
        )

        assert stored is not None
        assert stored.redaction_count == result.redaction_count
        assert stored.source_name is not None
        assert CANARY not in stored.source_name

        entry = repository.list_entries(
            incident_id,
            result.submission_id,
        )[0]

        fields = (
            entry.message,
            entry.exception,
            entry.service_name,
            entry.original_severity,
            entry.error_code,
            entry.correlation_id,
        )

        assert all(CANARY not in (value or "") for value in fields)


def test_source_name_redaction_accounting(
    service: LogIngestionService,
    settings: Settings,
    incident_id: UUID,
) -> None:
    from app.logs.sanitizer import LogSanitizer

    source_name = f"password={CANARY}"

    expected_name, expected_count = LogSanitizer(settings).sanitize_source_name(
        source_name
    )

    result = service.ingest(
        incident_id,
        b"INFO Application ready",
        LogFormat.TEXT,
        source_name=source_name,
    )

    assert expected_count > 0
    assert result.source_name == expected_name
    assert result.redaction_count == expected_count


@pytest.mark.parametrize(
    "source_name",
    [None, "", " ", "\t\r\n"],
)
def test_missing_source_name(
    service: LogIngestionService,
    incident_id: UUID,
    source_name: str | None,
) -> None:
    result = service.ingest(
        incident_id,
        b"INFO Application ready",
        LogFormat.TEXT,
        source_name=source_name,
    )

    assert result.source_name is None
    assert result.was_redacted is False


def test_clean_log_persists_without_evidence(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    result = service.ingest(
        incident_id,
        b"INFO Application ready",
        LogFormat.TEXT,
    )

    assert result.entry_count == 1
    assert result.has_diagnostic_evidence is False
    assert result.evidence.diagnostic_events == 0

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 1
    )


def test_missing_incident_rejected(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
) -> None:
    missing = uuid4()

    with pytest.raises(IncidentNotFoundError):
        service.ingest(
            missing,
            b"ERROR Database connection failed",
            LogFormat.TEXT,
        )

    assert (
        submission_count(
            session_factory,
            missing,
        )
        == 0
    )


def test_invalid_format_rejected(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        service.ingest(
            incident_id,
            b"Synthetic payload",
            cast(LogFormat, "unsupported"),
        )

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 0
    )


@pytest.mark.parametrize(
    ("source_format", "payload", "error_type"),
    [
        (
            LogFormat.TEXT,
            b"",
            InvalidLogPayloadError,
        ),
        (
            LogFormat.JSON,
            b'{"message":',
            MalformedLogError,
        ),
        (
            LogFormat.XML,
            b"<event>",
            MalformedLogError,
        ),
        (
            LogFormat.TEXT,
            b"\xff\xfe",
            InvalidLogEncodingError,
        ),
        (
            LogFormat.TEXT,
            b"x" * 8193,
            LogPayloadTooLargeError,
        ),
        (
            LogFormat.TEXT,
            b"INFO Ready\n" * 11,
            LogResourceLimitError,
        ),
        (
            LogFormat.XML,
            b'<!DOCTYPE event><event message="Ready"/>',
            UnsafeLogContentError,
        ),
        (
            LogFormat.TEXT,
            b"ERROR password=\nSYNTHETIC_SECRET_CANARY",
            UnsafeLogContentError,
        ),
    ],
)
def test_rejected_payload_creates_no_submission(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    source_format: LogFormat,
    payload: bytes,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        service.ingest(
            incident_id,
            payload,
            source_format,
        )

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 0
    )


def test_oversized_source_name_rejected(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    with pytest.raises(LogResourceLimitError):
        service.ingest(
            incident_id,
            b"INFO Ready",
            LogFormat.TEXT,
            source_name="x" * 201,
        )

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 0
    )


def test_exact_source_name_limit(
    service: LogIngestionService,
    incident_id: UUID,
) -> None:
    source_name = "x" * 200

    result = service.ingest(
        incident_id,
        b"INFO Ready",
        LogFormat.TEXT,
        source_name=source_name,
    )

    assert result.source_name == source_name


@pytest.mark.parametrize(
    ("source_name", "error_type"),
    [
        ("password=", UnsafeLogContentError),
        ("source\x00name", InvalidLogEncodingError),
    ],
)
def test_unsafe_source_name_rejected(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    source_name: str,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        service.ingest(
            incident_id,
            b"ERROR Database connection failed",
            LogFormat.TEXT,
            source_name=source_name,
        )

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 0
    )


def test_evidence_budget_enforced(
    service: LogIngestionService,
    settings: Settings,
    incident_id: UUID,
) -> None:
    payload = json.dumps(
        [
            {
                "severity": "ERROR",
                "message": ("Database connection failed " + "x" * 500),
            }
            for _ in range(10)
        ]
    ).encode("utf-8")

    result = service.ingest(
        incident_id,
        payload,
        LogFormat.JSON,
    )

    assert result.entry_count == 10
    assert result.evidence.diagnostic_events == 10

    assert result.evidence.selected_event_count <= (settings.log_max_evidence_entries)

    assert result.evidence.character_count <= (settings.log_max_evidence_chars)


def test_multiple_submissions_remain_separate(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    first = service.ingest(
        incident_id,
        b"ERROR Database connection failed",
        LogFormat.TEXT,
    )

    second = service.ingest(
        incident_id,
        b"CRITICAL Invalid signature",
        LogFormat.TEXT,
    )

    assert first.submission_id != second.submission_id

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 2
    )

    assert "DB-002" in first.evidence.events[0].rule_ids
    assert "SEC-001" in second.evidence.events[0].rule_ids
    assert "DB-002" not in second.evidence.events[0].rule_ids


def test_incident_attributes_not_modified(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    with session_factory() as session:
        incident = session.get(Incident, incident_id)

        assert incident is not None

        original = (
            incident.title,
            incident.description,
            incident.status,
            incident.priority,
            incident.category,
            incident.resolution,
            incident.updated_at,
        )

    service.ingest(
        incident_id,
        b"CRITICAL Invalid signature",
        LogFormat.TEXT,
    )

    with session_factory() as session:
        incident = session.get(Incident, incident_id)

        assert incident is not None

        assert (
            incident.title,
            incident.description,
            incident.status,
            incident.priority,
            incident.category,
            incident.resolution,
            incident.updated_at,
        ) == original


def test_ingestion_result_is_immutable(
    service: LogIngestionService,
    incident_id: UUID,
) -> None:
    result = service.ingest(
        incident_id,
        b"INFO Ready",
        LogFormat.TEXT,
    )

    with pytest.raises(FrozenInstanceError):
        type(result).__setattr__(result, "entry_count", 999)


def test_failure_after_database_writes_rolls_back(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_create = ApplicationLogRepository.create
    written_ids: list[UUID] = []

    def fail_after_create(
        repository: ApplicationLogRepository,
        identifier: UUID,
        log: SanitizedLog,
        *,
        source_name: str | None = None,
        source_redaction_count: int = 0,
    ) -> LogSubmission:
        submission = original_create(
            repository,
            identifier,
            log,
            source_name=source_name,
            source_redaction_count=source_redaction_count,
        )

        written_ids.append(submission.id)

        raise RuntimeError("Synthetic post-insertion failure.")

    with monkeypatch.context() as patch:
        patch.setattr(
            ApplicationLogRepository,
            "create",
            fail_after_create,
        )

        with pytest.raises(
            RuntimeError,
            match="Synthetic post-insertion failure",
        ):
            service.ingest(
                incident_id,
                b"ERROR Database connection failed",
                LogFormat.TEXT,
            )

    assert len(written_ids) == 1

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 0
    )

    with session_factory() as session:
        statement = (
            select(func.count())
            .select_from(LogEntry)
            .where(LogEntry.submission_id == written_ids[0])
        )

        assert session.execute(statement).scalar_one() == 0

    recovered = service.ingest(
        incident_id,
        b"INFO Application recovered",
        LogFormat.TEXT,
    )

    assert recovered.entry_count == 1

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 1
    )


def test_invalid_submission_preserves_existing_records(
    service: LogIngestionService,
    session_factory: sessionmaker[Session],
    incident_id: UUID,
) -> None:
    first = service.ingest(
        incident_id,
        b"ERROR Database connection failed",
        LogFormat.TEXT,
    )

    with pytest.raises(MalformedLogError):
        service.ingest(
            incident_id,
            b'{"message":',
            LogFormat.JSON,
        )

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 1
    )

    with session_factory() as session:
        stored = ApplicationLogRepository(session).get_by_id(
            incident_id,
            first.submission_id,
        )

        assert stored is not None
        assert stored.entry_count == 1

    recovered = service.ingest(
        incident_id,
        b"ERROR Database service restored.",
        LogFormat.TEXT,
    )

    assert recovered.submission_id != first.submission_id
    assert recovered.entry_count == 1

    assert (
        submission_count(
            session_factory,
            incident_id,
        )
        == 2
    )

    with session_factory() as session:
        repository = ApplicationLogRepository(session)

        original_submission = repository.get_by_id(
            incident_id,
            first.submission_id,
        )

        recovered_submission = repository.get_by_id(
            incident_id,
            recovered.submission_id,
        )

        assert original_submission is not None
        assert original_submission.entry_count == 1
        assert recovered_submission is not None
        assert recovered_submission.entry_count == 1
