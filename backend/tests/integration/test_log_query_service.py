from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import IncidentNotFoundError
from app.logs.exceptions import (
    InvalidLogPaginationError,
    LogEntryNotFoundError,
    LogPersistenceIntegrityError,
    LogSubmissionNotFoundError,
)
from app.logs.ingestion_contracts import LogIngestionResult
from app.logs.query_contracts import (
    LogEntryRecord,
    LogSubmissionRecord,
)
from app.models.application_log import LogEntry, LogSubmission
from app.models.incident import Incident
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.exceptions import LogResourceLimitError
from app.repositories.application_log import ApplicationLogRepository
from app.services.log_ingestion import LogIngestionService
from app.services.log_query import LogQueryService


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_entries": 100,
            "log_max_evidence_entries": 20,
            "log_max_evidence_chars": 8000,
        }
    )


@pytest.fixture
def factory(
    integration_engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=integration_engine,
        expire_on_commit=True,
        autoflush=False,
    )


@pytest.fixture
def incident_ids(
    factory: sessionmaker[Session],
) -> Iterator[tuple[UUID, UUID]]:
    identifiers = (uuid4(), uuid4())

    try:
        with factory.begin() as session:
            session.add_all(
                [
                    Incident(
                        id=identifier,
                        title="log-query-service-test",
                        description="Synthetic query integration test.",
                    )
                    for identifier in identifiers
                ]
            )

        yield identifiers

    finally:
        with factory.begin() as session:
            session.execute(delete(Incident).where(Incident.id.in_(identifiers)))


@pytest.fixture
def ingestion(
    factory: sessionmaker[Session],
    settings: Settings,
) -> LogIngestionService:
    return LogIngestionService(factory, settings)


@pytest.fixture
def query(
    factory: sessionmaker[Session],
    settings: Settings,
) -> LogQueryService:
    return LogQueryService(factory, settings)


@pytest.fixture
def submitted(
    ingestion: LogIngestionService,
    incident_ids: tuple[UUID, UUID],
) -> LogIngestionResult:
    payload = (
        b"INFO Workflow started\n"
        b"2026-11-24T10:30:00-05:00 ERROR "
        b"[database] Database connection failed\n"
        b"CRITICAL Invalid signature\n"
        b"ERROR Authentication failed "
        b"password=SYNTHETIC_SECRET_CANARY"
    )

    return ingestion.ingest(
        incident_ids[0],
        payload,
        LogFormat.TEXT,
        source_name="synthetic-service",
    )


def test_get_submission(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    result = query.get_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert isinstance(result, LogSubmissionRecord)
    assert result.id == submitted.submission_id
    assert result.incident_id == submitted.incident_id
    assert result.source_format == submitted.source_format
    assert result.source_name == submitted.source_name
    assert result.payload_bytes == submitted.payload_bytes
    assert result.entry_count == submitted.entry_count
    assert result.redaction_count == submitted.redaction_count
    assert result.created_at == submitted.created_at


def test_submission_not_found(
    query: LogQueryService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        query.get_submission(
            incident_ids[0],
            uuid4(),
        )


def test_missing_incident(
    query: LogQueryService,
) -> None:
    with pytest.raises(IncidentNotFoundError):
        query.list_submissions(uuid4())


def test_empty_submission_page(
    query: LogQueryService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    page = query.list_submissions(incident_ids[0])

    assert page.items == ()
    assert page.total == 0
    assert page.offset == 0
    assert page.limit == 20
    assert page.has_more is False


def test_submission_pagination(
    query: LogQueryService,
    ingestion: LogIngestionService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    identifier = incident_ids[0]

    for _ in range(5):
        ingestion.ingest(
            identifier,
            b"INFO Ready",
            LogFormat.TEXT,
        )

    complete = query.list_submissions(identifier)

    first = query.list_submissions(
        identifier,
        offset=0,
        limit=2,
    )

    second = query.list_submissions(
        identifier,
        offset=2,
        limit=2,
    )

    third = query.list_submissions(
        identifier,
        offset=4,
        limit=2,
    )

    assert first.total == 5
    assert first.has_more is True
    assert second.has_more is True
    assert third.has_more is False

    assert first.items + second.items + third.items == (complete.items)


@pytest.mark.parametrize(
    ("offset", "limit"),
    [(-1, 20), (0, 0), (0, -1), (0, 101)],
)
def test_invalid_submission_pagination(
    query: LogQueryService,
    incident_ids: tuple[UUID, UUID],
    offset: int,
    limit: int,
) -> None:
    with pytest.raises(InvalidLogPaginationError):
        query.list_submissions(
            incident_ids[0],
            offset=offset,
            limit=limit,
        )


@pytest.mark.parametrize("limit", [1, 20, 100])
def test_valid_pagination_boundaries(
    query: LogQueryService,
    incident_ids: tuple[UUID, UUID],
    limit: int,
) -> None:
    page = query.list_submissions(
        incident_ids[0],
        limit=limit,
    )

    assert page.limit == limit


def test_list_entries(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    page = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert page.total == 4
    assert page.has_more is False

    assert [entry.position for entry in page.items] == [1, 2, 3, 4]

    assert all(isinstance(entry, LogEntryRecord) for entry in page.items)


def test_get_entry(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    page = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    )

    expected = page.items[1]

    result = query.get_entry(
        submitted.incident_id,
        submitted.submission_id,
        expected.id,
    )

    assert result == expected
    assert result.submission_id == submitted.submission_id
    assert result.position == 2
    assert result.severity == LogSeverity.ERROR
    assert result.service_name == "database"
    assert result.message == "Database connection failed"

    assert result.event_timestamp == datetime(2026, 11, 24, 15, 30, tzinfo=UTC)


def test_entry_not_found(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    with pytest.raises(LogEntryNotFoundError):
        query.get_entry(
            submitted.incident_id,
            submitted.submission_id,
            uuid4(),
        )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (LogSeverity.INFO, 1),
        (LogSeverity.ERROR, 2),
        (LogSeverity.CRITICAL, 1),
        (LogSeverity.WARNING, 0),
        (LogSeverity.UNKNOWN, 0),
        (LogSeverity.DEBUG, 0),
        (LogSeverity.TRACE, 0),
    ],
)
def test_entry_severity_filter(
    query: LogQueryService,
    submitted: LogIngestionResult,
    severity: LogSeverity,
    expected: int,
) -> None:
    page = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
        severity=severity,
    )

    assert page.total == expected
    assert len(page.items) == expected

    assert all(entry.severity == severity for entry in page.items)


def test_filtered_entry_pagination(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    first = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
        severity=LogSeverity.ERROR,
        limit=1,
    )

    second = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
        severity=LogSeverity.ERROR,
        offset=1,
        limit=1,
    )

    assert first.total == 2
    assert first.has_more is True
    assert second.has_more is False
    assert first.items[0].position == 2
    assert second.items[0].position == 4


@pytest.mark.parametrize(
    ("offset", "limit"),
    [(-1, 20), (0, 0), (0, 101)],
)
def test_invalid_entry_pagination(
    query: LogQueryService,
    submitted: LogIngestionResult,
    offset: int,
    limit: int,
) -> None:
    with pytest.raises(InvalidLogPaginationError):
        query.list_entries(
            submitted.incident_id,
            submitted.submission_id,
            offset=offset,
            limit=limit,
        )


def test_offset_beyond_available_records(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    page = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
        offset=100,
    )

    assert page.total == 4
    assert page.items == ()
    assert page.has_more is False


def test_submission_list_isolation(
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    page = query.list_submissions(incident_ids[1])

    assert page.items == ()
    assert page.total == 0

    assert submitted.incident_id != incident_ids[1]


def test_cross_incident_submission_rejected(
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        query.get_submission(
            incident_ids[1],
            submitted.submission_id,
        )


def test_cross_incident_entries_rejected(
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        query.list_entries(
            incident_ids[1],
            submitted.submission_id,
        )


def test_cross_submission_entry_rejected(
    query: LogQueryService,
    ingestion: LogIngestionService,
    submitted: LogIngestionResult,
) -> None:
    other = ingestion.ingest(
        submitted.incident_id,
        b"INFO Ready",
        LogFormat.TEXT,
    )

    entry = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    ).items[0]

    with pytest.raises(LogEntryNotFoundError):
        query.get_entry(
            submitted.incident_id,
            other.submission_id,
            entry.id,
        )


def test_evidence_reconstruction_matches_ingestion(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    reconstructed = query.get_evidence(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert reconstructed == submitted.evidence

    assert reconstructed.to_json() == (submitted.evidence.to_json())

    assert reconstructed.total_events == 4
    assert reconstructed.diagnostic_events == 3


def test_reconstructed_evidence_is_redacted(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    result = query.get_evidence(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert "SYNTHETIC_SECRET_CANARY" not in result.to_json()

    assert any("AUTH-001" in event.rule_ids for event in result.events)


def test_clean_log_evidence_reconstruction(
    query: LogQueryService,
    ingestion: LogIngestionService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    submitted = ingestion.ingest(
        incident_ids[0],
        b"INFO Application ready",
        LogFormat.TEXT,
    )

    result = query.get_evidence(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert result.has_evidence is False
    assert result.total_events == 1
    assert result.diagnostic_events == 0


def test_current_evidence_limits_enforced(
    factory: sessionmaker[Session],
    settings: Settings,
    submitted: LogIngestionResult,
) -> None:
    limited = settings.model_copy(
        update={
            "log_max_evidence_entries": 1,
            "log_max_evidence_chars": 256,
        }
    )

    result = LogQueryService(factory, limited).get_evidence(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert result.selected_event_count <= 1
    assert result.character_count <= 256
    assert result.diagnostic_events == 3


def test_cross_incident_evidence_rejected(
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        query.get_evidence(
            incident_ids[1],
            submitted.submission_id,
        )


def test_reconstruction_entry_limit(
    factory: sessionmaker[Session],
    settings: Settings,
    submitted: LogIngestionResult,
) -> None:
    limited = settings.model_copy(update={"log_max_entries": 2})

    with pytest.raises(LogResourceLimitError):
        LogQueryService(factory, limited).get_evidence(
            submitted.incident_id,
            submitted.submission_id,
        )


@pytest.mark.parametrize("incorrect_count", [3, 5])
def test_reconstruction_count_mismatch_rejected(
    query: LogQueryService,
    factory: sessionmaker[Session],
    submitted: LogIngestionResult,
    incorrect_count: int,
) -> None:
    with factory.begin() as session:
        record = session.get(
            LogSubmission,
            submitted.submission_id,
        )

        assert record is not None
        record.entry_count = incorrect_count

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            submitted.incident_id,
            submitted.submission_id,
        )


def test_reconstruction_invalid_position_rejected(
    query: LogQueryService,
    factory: sessionmaker[Session],
    submitted: LogIngestionResult,
) -> None:
    page = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    )

    with factory.begin() as session:
        entry = session.get(LogEntry, page.items[-1].id)

        assert entry is not None
        entry.position = 100

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            submitted.incident_id,
            submitted.submission_id,
        )


def test_invalid_timestamp_rejected(
    query: LogQueryService,
    submitted: LogIngestionResult,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ApplicationLogRepository.list_entries

    def invalid_entries(
        repository: ApplicationLogRepository,
        incident_id: UUID,
        submission_id: UUID,
        *,
        offset: int = 0,
        limit: int = 100,
        severity: LogSeverity | None = None,
    ) -> list[LogEntry]:
        entries = original(
            repository,
            incident_id,
            submission_id,
            offset=offset,
            limit=limit,
            severity=severity,
        )

        entries[0].event_timestamp = datetime(2026, 11, 24, 15, 30)

        return entries

    monkeypatch.setattr(
        ApplicationLogRepository,
        "list_entries",
        invalid_entries,
    )

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            submitted.incident_id,
            submitted.submission_id,
        )


def test_delete_submission_commits(
    query: LogQueryService,
    factory: sessionmaker[Session],
    submitted: LogIngestionResult,
) -> None:
    query.delete_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    with factory() as session:
        assert (
            session.get(
                LogSubmission,
                submitted.submission_id,
            )
            is None
        )

        statement = (
            select(func.count())
            .select_from(LogEntry)
            .where(LogEntry.submission_id == submitted.submission_id)
        )

        assert session.execute(statement).scalar_one() == 0

        assert (
            session.get(
                Incident,
                submitted.incident_id,
            )
            is not None
        )


def test_delete_missing_submission(
    query: LogQueryService,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        query.delete_submission(
            incident_ids[0],
            uuid4(),
        )


def test_delete_cross_incident_rejected(
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with pytest.raises(LogSubmissionNotFoundError):
        query.delete_submission(
            incident_ids[1],
            submitted.submission_id,
        )

    assert (
        query.get_submission(
            submitted.incident_id,
            submitted.submission_id,
        ).entry_count
        == 4
    )


def test_delete_rollback(
    query: LogQueryService,
    submitted: LogIngestionResult,
    monkeypatch: pytest.MonkeyPatch,
    factory: sessionmaker[Session],
) -> None:
    original = ApplicationLogRepository.delete

    def fail_after_delete(
        repository: ApplicationLogRepository,
        incident_id: UUID,
        submission_id: UUID,
    ) -> bool:
        original(
            repository,
            incident_id,
            submission_id,
        )

        raise RuntimeError("Synthetic deletion failure.")

    with monkeypatch.context() as patch:
        patch.setattr(
            ApplicationLogRepository,
            "delete",
            fail_after_delete,
        )

        with pytest.raises(
            RuntimeError,
            match="Synthetic deletion failure",
        ):
            query.delete_submission(
                submitted.incident_id,
                submitted.submission_id,
            )

    assert (
        query.get_submission(
            submitted.incident_id,
            submitted.submission_id,
        ).entry_count
        == 4
    )

    assert (
        query.list_entries(
            submitted.incident_id,
            submitted.submission_id,
        ).total
        == 4
    )

    from sqlalchemy import func

    incident_id = submitted.incident_id
    submission_id = submitted.submission_id

    with factory() as session:
        incident = session.get(Incident, incident_id)

        assert incident is not None

        incident_before = {
            column.name: getattr(incident, column.name)
            for column in Incident.__table__.columns
        }

        restored_submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert restored_submission is not None
        assert restored_submission.entry_count == 4

        restored_entries = session.scalars(
            select(LogEntry)
            .where(LogEntry.submission_id == submission_id)
            .order_by(LogEntry.position)
        ).all()

        assert len(restored_entries) == 4

        entry_ids = {entry.id for entry in restored_entries}

        assert len(entry_ids) == 4

    query.delete_submission(
        incident_id,
        submission_id,
    )

    with factory() as session:
        assert (
            session.get(
                LogSubmission,
                submission_id,
            )
            is None
        )

        remaining_entries = session.scalar(
            select(func.count())
            .select_from(LogEntry)
            .where(LogEntry.submission_id == submission_id)
        )

        assert remaining_entries == 0

        for entry_id in entry_ids:
            assert (
                session.get(
                    LogEntry,
                    entry_id,
                )
                is None
            )

        incident = session.get(
            Incident,
            incident_id,
        )

        assert incident is not None

        incident_after = {
            column.name: getattr(incident, column.name)
            for column in Incident.__table__.columns
        }

        assert incident_after == incident_before


def test_submission_record_is_immutable(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    record = query.get_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    with pytest.raises(FrozenInstanceError):
        type(record).__setattr__(record, "entry_count", 999)


def test_entry_record_is_immutable(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    record = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    ).items[0]

    with pytest.raises(FrozenInstanceError):
        type(record).__setattr__(record, "message", "Modified")


def test_entry_representation_hides_message(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    record = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    ).items[1]

    assert record.message not in repr(record)


def test_query_preserves_incident_and_submission(
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    before = query.get_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    )

    query.get_evidence(
        submitted.incident_id,
        submitted.submission_id,
    )

    after = query.get_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert before == after


STORED_SECURITY_CANARY = "SYNTHETIC_STORED_SECURITY_CANARY"

STORED_SECURITY_FIELDS = (
    "message",
    "original_severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)

STORED_UNSAFE_VALUES = (
    f"password={STORED_SECURITY_CANARY}",
    f"api key={STORED_SECURITY_CANARY}",
    f"secret key={STORED_SECURITY_CANARY}",
    f"Bearer {STORED_SECURITY_CANARY}",
    f"password=[REDACTED_SECRET]{STORED_SECURITY_CANARY}",
    f"Bearer [REDACTED_TOKEN]{STORED_SECURITY_CANARY}",
    f"Bearer [REDACTED_TOKEN={STORED_SECURITY_CANARY}]",
    f"postgresql://user:{STORED_SECURITY_CANARY}@localhost/db",
)


@pytest.mark.parametrize("field", STORED_SECURITY_FIELDS)
@pytest.mark.parametrize("value", STORED_UNSAFE_VALUES)
@pytest.mark.parametrize("operation", ["get", "list"])
def test_stored_entry_security_rejects_unsafe_content(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    field: str,
    value: str,
    operation: str,
) -> None:
    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submitted.submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry_id = entry.id

        setattr(entry, field, value)

    with pytest.raises(LogPersistenceIntegrityError) as error:
        if operation == "get":
            query.get_entry(
                submitted.incident_id,
                submitted.submission_id,
                entry_id,
            )
        else:
            query.list_entries(
                submitted.incident_id,
                submitted.submission_id,
            )

    assert STORED_SECURITY_CANARY not in str(error.value)

    with factory() as session:
        stored = session.get(LogEntry, entry_id)

        assert stored is not None
        assert getattr(stored, field) == value


@pytest.mark.parametrize("value", STORED_UNSAFE_VALUES)
@pytest.mark.parametrize("operation", ["get", "list"])
def test_stored_submission_security_rejects_unsafe_metadata(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    value: str,
    operation: str,
) -> None:
    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submitted.submission_id,
        )

        assert submission is not None

        submission.source_name = value

    with pytest.raises(LogPersistenceIntegrityError) as error:
        if operation == "get":
            query.get_submission(
                submitted.incident_id,
                submitted.submission_id,
            )
        else:
            query.list_submissions(
                submitted.incident_id,
            )

    assert STORED_SECURITY_CANARY not in str(error.value)

    with factory() as session:
        stored = session.get(
            LogSubmission,
            submitted.submission_id,
        )

        assert stored is not None
        assert stored.source_name == value


@pytest.mark.parametrize("field", STORED_SECURITY_FIELDS)
@pytest.mark.parametrize(
    "value",
    [
        "Synthetic diagnostic information.",
        "password=[REDACTED_SECRET]",
        "Bearer [REDACTED_TOKEN]",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        "[REDACTED_EMAIL]",
        "[REDACTED]",
    ],
)
def test_stored_entry_security_preserves_safe_content(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    field: str,
    value: str,
) -> None:
    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submitted.submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry_id = entry.id

        setattr(entry, field, value)

    result = query.get_entry(
        submitted.incident_id,
        submitted.submission_id,
        entry_id,
    )

    assert getattr(result, field) == value

    page = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert getattr(page.items[1], field) == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        "application.log",
        "password=[REDACTED_SECRET]",
        "Bearer [REDACTED_TOKEN]",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        "[REDACTED_EMAIL]",
        "[REDACTED]",
    ],
)
def test_stored_submission_security_preserves_safe_metadata(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    value: str | None,
) -> None:
    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submitted.submission_id,
        )

        assert submission is not None

        submission.source_name = value

    result = query.get_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    assert result.source_name == value

    page = query.list_submissions(
        submitted.incident_id,
    )

    assert page.items[0].source_name == value


def test_stored_entry_security_validates_returned_page(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submitted.submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry.message = f"password={STORED_SECURITY_CANARY}"

    first = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
        offset=0,
        limit=1,
    )

    assert first.total == 4
    assert first.items[0].position == 1

    with pytest.raises(LogPersistenceIntegrityError) as error:
        query.list_entries(
            submitted.incident_id,
            submitted.submission_id,
            offset=1,
            limit=1,
        )

    assert STORED_SECURITY_CANARY not in str(error.value)

    third = query.list_entries(
        submitted.incident_id,
        submitted.submission_id,
        offset=2,
        limit=1,
    )

    assert third.items[0].position == 3


def test_stored_entry_security_preserves_incident_scope(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submitted.submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry_id = entry.id

        entry.message = f"password={STORED_SECURITY_CANARY}"

    with pytest.raises(LogSubmissionNotFoundError):
        query.get_entry(
            incident_ids[1],
            submitted.submission_id,
            entry_id,
        )

    with pytest.raises(LogSubmissionNotFoundError):
        query.list_entries(
            incident_ids[1],
            submitted.submission_id,
        )


def test_stored_submission_security_preserves_incident_scope(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
) -> None:
    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submitted.submission_id,
        )

        assert submission is not None

        submission.source_name = f"password={STORED_SECURITY_CANARY}"

    with pytest.raises(LogSubmissionNotFoundError):
        query.get_submission(
            incident_ids[1],
            submitted.submission_id,
        )

    page = query.list_submissions(incident_ids[1])

    assert page.total == 0
    assert page.items == ()


def test_stored_content_security_allows_deletion(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
) -> None:
    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submitted.submission_id,
        )

        assert submission is not None

        submission.source_name = f"password={STORED_SECURITY_CANARY}"

    query.delete_submission(
        submitted.incident_id,
        submitted.submission_id,
    )

    with factory() as session:
        assert (
            session.get(
                LogSubmission,
                submitted.submission_id,
            )
            is None
        )

        entries = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submitted.submission_id,
            )
        ).all()

        assert entries == []


@pytest.mark.parametrize(
    "operation",
    ["evidence", "session", "ai_context"],
)
@pytest.mark.parametrize("field", STORED_SECURITY_FIELDS)
@pytest.mark.parametrize("value", STORED_UNSAFE_VALUES)
@pytest.mark.parametrize("position", [1, 2])
def test_stored_evidence_security_rejects_unsafe_entry(
    factory: sessionmaker[Session],
    settings: Settings,
    query: LogQueryService,
    submitted: LogIngestionResult,
    operation: str,
    field: str,
    value: str,
    position: int,
) -> None:
    from app.services.ai_log_context import AILogContextService

    incident_id = submitted.incident_id
    submission_id = submitted.submission_id

    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == position,
            )
        ).one()

        entry_id = entry.id

        setattr(entry, field, value)

    with pytest.raises(LogPersistenceIntegrityError) as error:
        if operation == "evidence":
            query.get_evidence(
                incident_id,
                submission_id,
            )
        elif operation == "session":
            with factory() as session:
                query.get_evidence_in_session(
                    session,
                    incident_id,
                    submission_id,
                )
        else:
            AILogContextService(
                query,
                settings,
            ).build_context(
                incident_id,
                submission_id,
            )

    assert STORED_SECURITY_CANARY not in str(error.value)

    with factory() as session:
        persisted = session.get(LogEntry, entry_id)

        assert persisted is not None

        assert getattr(persisted, field) == value


@pytest.mark.parametrize(
    "operation",
    ["evidence", "session", "ai_context"],
)
@pytest.mark.parametrize("value", STORED_UNSAFE_VALUES)
def test_stored_evidence_security_rejects_unsafe_source_name(
    factory: sessionmaker[Session],
    settings: Settings,
    query: LogQueryService,
    submitted: LogIngestionResult,
    operation: str,
    value: str,
) -> None:
    from app.services.ai_log_context import AILogContextService

    incident_id = submitted.incident_id
    submission_id = submitted.submission_id

    with factory.begin() as session:
        submission = session.get(
            LogSubmission,
            submission_id,
        )

        assert submission is not None

        submission.source_name = value

    with pytest.raises(LogPersistenceIntegrityError) as error:
        if operation == "evidence":
            query.get_evidence(
                incident_id,
                submission_id,
            )
        elif operation == "session":
            with factory() as session:
                query.get_evidence_in_session(
                    session,
                    incident_id,
                    submission_id,
                )
        else:
            AILogContextService(
                query,
                settings,
            ).build_context(
                incident_id,
                submission_id,
            )

    assert STORED_SECURITY_CANARY not in str(error.value)

    with factory() as session:
        persisted = session.get(
            LogSubmission,
            submission_id,
        )

        assert persisted is not None
        assert persisted.source_name == value


@pytest.mark.parametrize(
    "value",
    [
        "password=[REDACTED_SECRET]",
        "Bearer [REDACTED_TOKEN]",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        "[REDACTED_EMAIL]",
        "[REDACTED]",
        "Synthetic diagnostic information.",
    ],
)
def test_stored_evidence_security_preserves_safe_content(
    factory: sessionmaker[Session],
    settings: Settings,
    query: LogQueryService,
    submitted: LogIngestionResult,
    value: str,
) -> None:
    from app.services.ai_log_context import AILogContextService

    incident_id = submitted.incident_id
    submission_id = submitted.submission_id

    message = f"Database connection failed; {value}"

    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry_id = entry.id
        entry.message = message

    evidence = query.get_evidence(
        incident_id,
        submission_id,
    )

    with factory() as session:
        transactional_evidence = query.get_evidence_in_session(
            session,
            incident_id,
            submission_id,
        )

    context = AILogContextService(
        query,
        settings,
    ).build_context(
        incident_id,
        submission_id,
    )

    assert evidence == transactional_evidence
    assert context.evidence == evidence

    event = next(event for event in evidence.events if event.position == 2)

    assert event.message == message

    assert context.incident_id == incident_id
    assert context.submission_id == submission_id

    with factory() as session:
        persisted = session.get(LogEntry, entry_id)

        assert persisted is not None
        assert persisted.message == message


@pytest.mark.parametrize(
    "operation",
    ["evidence", "session", "ai_context"],
)
def test_stored_evidence_security_preserves_incident_scope(
    factory: sessionmaker[Session],
    settings: Settings,
    query: LogQueryService,
    submitted: LogIngestionResult,
    incident_ids: tuple[UUID, UUID],
    operation: str,
) -> None:
    from app.services.ai_log_context import AILogContextService

    other_incident_id = next(
        identifier for identifier in incident_ids if identifier != submitted.incident_id
    )

    submission_id = submitted.submission_id

    with factory.begin() as session:
        entry = session.scalars(
            select(LogEntry).where(
                LogEntry.submission_id == submission_id,
                LogEntry.position == 2,
            )
        ).one()

        entry.message = f"password={STORED_SECURITY_CANARY}"

    with pytest.raises(LogSubmissionNotFoundError):
        if operation == "evidence":
            query.get_evidence(
                other_incident_id,
                submission_id,
            )
        elif operation == "session":
            with factory() as session:
                query.get_evidence_in_session(
                    session,
                    other_incident_id,
                    submission_id,
                )
        else:
            AILogContextService(
                query,
                settings,
            ).build_context(
                other_incident_id,
                submission_id,
            )


@pytest.mark.parametrize(
    "field",
    (*STORED_SECURITY_FIELDS, "source_name"),
)
@pytest.mark.parametrize("value", STORED_UNSAFE_VALUES)
@pytest.mark.parametrize("position", [1, 4])
def test_stored_evidence_security_prevents_extraction(
    factory: sessionmaker[Session],
    query: LogQueryService,
    submitted: LogIngestionResult,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    position: int,
) -> None:
    from unittest.mock import MagicMock

    with factory.begin() as session:
        if field == "source_name":
            submission = session.get(
                LogSubmission,
                submitted.submission_id,
            )

            assert submission is not None
            submission.source_name = value
        else:
            entry = session.scalars(
                select(LogEntry).where(
                    LogEntry.submission_id == submitted.submission_id,
                    LogEntry.position == position,
                )
            ).one()

            setattr(entry, field, value)

    extractor = MagicMock(
        side_effect=AssertionError("Unsafe stored content reached evidence extraction.")
    )

    monkeypatch.setattr(
        type(query._extractor),
        "extract",
        extractor,
    )

    with pytest.raises(LogPersistenceIntegrityError) as error:
        query.get_evidence(
            submitted.incident_id,
            submitted.submission_id,
        )

    assert STORED_SECURITY_CANARY not in str(error.value)

    extractor.assert_not_called()
