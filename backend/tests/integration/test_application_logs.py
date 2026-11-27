from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from app.models import Incident, LogEntry, LogSubmission
from app.models.log_enums import LogFormat, LogSeverity


@pytest.fixture
def log_incident(
    integration_session: Session,
) -> Incident:
    incident = Incident(
        title="Synthetic log integration test",
        description="Application log persistence verification.",
    )

    integration_session.add(incident)
    integration_session.flush()

    return incident


def create_submission(
    session: Session,
    incident_id: UUID,
    source_format: LogFormat = LogFormat.XML,
) -> LogSubmission:
    submission = LogSubmission(
        incident_id=incident_id,
        source_format=source_format,
        source_name="synthetic-application",
        payload_bytes=1024,
        entry_count=1,
        redaction_count=0,
    )

    session.add(submission)
    session.flush()

    return submission


def create_entry(
    session: Session,
    submission_id: UUID,
    position: int = 1,
    severity: LogSeverity = LogSeverity.ERROR,
) -> LogEntry:
    entry = LogEntry(
        submission_id=submission_id,
        position=position,
        severity=severity,
        message="Synthetic database connection failure.",
        service_name="database-service",
        error_code="DB_CONNECTION_ERROR",
        correlation_id="synthetic-correlation-id",
    )

    session.add(entry)
    session.flush()

    return entry


def test_submission_persistence(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    submission_id = submission.id

    integration_session.expire_all()

    persisted = integration_session.get(
        LogSubmission,
        submission_id,
    )

    assert persisted is not None
    assert persisted.incident_id == log_incident.id
    assert persisted.source_format == LogFormat.XML
    assert persisted.source_name == "synthetic-application"
    assert persisted.payload_bytes == 1024
    assert persisted.entry_count == 1
    assert persisted.redaction_count == 0
    assert persisted.created_at is not None
    assert persisted.created_at.tzinfo is not None


def test_entry_persistence(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    entry = create_entry(
        integration_session,
        submission.id,
    )

    entry_id = entry.id

    integration_session.expire_all()

    persisted = integration_session.get(
        LogEntry,
        entry_id,
    )

    assert persisted is not None
    assert persisted.submission_id == submission.id
    assert persisted.position == 1
    assert persisted.severity == LogSeverity.ERROR
    assert persisted.message == ("Synthetic database connection failure.")
    assert persisted.service_name == "database-service"
    assert persisted.error_code == "DB_CONNECTION_ERROR"
    assert persisted.correlation_id == "synthetic-correlation-id"


@pytest.mark.parametrize(
    "source_format",
    list(LogFormat),
)
def test_log_format_persistence(
    integration_session: Session,
    log_incident: Incident,
    source_format: LogFormat,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
        source_format,
    )

    integration_session.refresh(submission)

    assert submission.source_format == source_format


@pytest.mark.parametrize(
    "severity",
    list(LogSeverity),
)
def test_log_severity_persistence(
    integration_session: Session,
    log_incident: Incident,
    severity: LogSeverity,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    entry = create_entry(
        integration_session,
        submission.id,
        severity=severity,
    )

    integration_session.refresh(entry)

    assert entry.severity == severity


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        (
            "payload_bytes",
            0,
            "ck_log_submissions_payload_bytes_positive",
        ),
        (
            "payload_bytes",
            -1,
            "ck_log_submissions_payload_bytes_positive",
        ),
        (
            "entry_count",
            0,
            "ck_log_submissions_entry_count_positive",
        ),
        (
            "entry_count",
            -1,
            "ck_log_submissions_entry_count_positive",
        ),
        (
            "redaction_count",
            -1,
            "ck_log_submissions_redaction_count_nonnegative",
        ),
    ],
)
def test_submission_check_constraints(
    integration_session: Session,
    log_incident: Incident,
    field: str,
    value: int,
    constraint: str,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            setattr(submission, field, value)
            integration_session.flush()

    assert constraint in str(captured.value.orig)


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        (
            "position",
            0,
            "ck_log_entries_position_positive",
        ),
        (
            "position",
            -1,
            "ck_log_entries_position_positive",
        ),
        (
            "message",
            "",
            "ck_log_entries_message_nonempty",
        ),
        (
            "message",
            "   ",
            "ck_log_entries_message_nonempty",
        ),
    ],
)
def test_entry_check_constraints(
    integration_session: Session,
    log_incident: Incident,
    field: str,
    value: int | str,
    constraint: str,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    entry = create_entry(
        integration_session,
        submission.id,
    )

    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            setattr(entry, field, value)
            integration_session.flush()

    assert constraint in str(captured.value.orig)


def test_submission_foreign_key(
    integration_session: Session,
) -> None:
    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            create_submission(
                integration_session,
                uuid4(),
            )

    assert "fk_log_submissions_incident_id_incidents" in str(captured.value.orig)


def test_entry_foreign_key(
    integration_session: Session,
) -> None:
    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            create_entry(
                integration_session,
                uuid4(),
            )

    assert "fk_log_entries_submission_id_log_submissions" in str(captured.value.orig)


def test_duplicate_position_rejected(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    create_entry(
        integration_session,
        submission.id,
    )

    with pytest.raises(IntegrityError) as captured:
        with integration_session.begin_nested():
            create_entry(
                integration_session,
                submission.id,
            )

    assert "uq_log_entries_submission_id" in str(captured.value.orig)


def test_positions_reusable_across_submissions(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    first = create_submission(
        integration_session,
        log_incident.id,
    )

    second = create_submission(
        integration_session,
        log_incident.id,
    )

    first_entry = create_entry(
        integration_session,
        first.id,
    )

    second_entry = create_entry(
        integration_session,
        second.id,
    )

    assert first_entry.position == second_entry.position
    assert first_entry.id != second_entry.id
    assert first_entry.submission_id != second_entry.submission_id


def test_multiple_entry_positions(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    submission.entry_count = 3

    for position in [3, 1, 2]:
        create_entry(
            integration_session,
            submission.id,
            position=position,
        )

    statement = (
        select(LogEntry)
        .where(LogEntry.submission_id == submission.id)
        .order_by(LogEntry.position)
    )

    entries = integration_session.scalars(statement).all()

    assert [entry.position for entry in entries] == [1, 2, 3]
    assert len(entries) == submission.entry_count


def test_submission_cascade_deletion(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    submission_id = submission.id

    create_entry(
        integration_session,
        submission_id,
    )

    integration_session.delete(submission)
    integration_session.flush()

    count = integration_session.scalar(
        select(func.count())
        .select_from(LogEntry)
        .where(LogEntry.submission_id == submission_id)
    )

    assert count == 0
    assert integration_session.get(Incident, log_incident.id) is not None


def test_incident_cascade_deletion(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    incident_id = log_incident.id

    submission = create_submission(
        integration_session,
        incident_id,
    )

    submission_id = submission.id

    create_entry(
        integration_session,
        submission_id,
    )

    integration_session.delete(log_incident)
    integration_session.flush()

    submission_count = integration_session.scalar(
        select(func.count())
        .select_from(LogSubmission)
        .where(LogSubmission.incident_id == incident_id)
    )

    entry_count = integration_session.scalar(
        select(func.count())
        .select_from(LogEntry)
        .where(LogEntry.submission_id == submission_id)
    )

    assert submission_count == 0
    assert entry_count == 0


def test_transaction_rollback(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission_id = uuid4()
    entry_id = uuid4()

    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with integration_session.begin_nested():
            submission = LogSubmission(
                id=submission_id,
                incident_id=log_incident.id,
                source_format=LogFormat.JSON,
                payload_bytes=100,
                entry_count=1,
                redaction_count=0,
            )

            integration_session.add(submission)
            integration_session.flush()

            entry = LogEntry(
                id=entry_id,
                submission_id=submission_id,
                position=1,
                severity=LogSeverity.ERROR,
                message="Synthetic failure",
            )

            integration_session.add(entry)
            integration_session.flush()

            raise RuntimeError("synthetic rollback")

    assert (
        integration_session.get(
            LogSubmission,
            submission_id,
        )
        is None
    )

    assert (
        integration_session.get(
            LogEntry,
            entry_id,
        )
        is None
    )

    assert (
        integration_session.get(
            Incident,
            log_incident.id,
        )
        is not None
    )


def test_incident_log_isolation(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    other_incident = Incident(
        title="Synthetic independent incident",
        description="Independent log history.",
    )

    integration_session.add(other_incident)
    integration_session.flush()

    first = create_submission(
        integration_session,
        log_incident.id,
    )

    second = create_submission(
        integration_session,
        other_incident.id,
    )

    create_entry(integration_session, first.id)
    create_entry(integration_session, second.id)

    integration_session.delete(log_incident)
    integration_session.flush()

    count = integration_session.scalar(
        select(func.count())
        .select_from(LogEntry)
        .where(LogEntry.submission_id == second.id)
    )

    assert count == 1

    assert (
        integration_session.get(
            LogSubmission,
            second.id,
        )
        is not None
    )


def test_timezone_aware_timestamp(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    timestamp = datetime(
        2026,
        11,
        24,
        15,
        30,
        tzinfo=UTC,
    )

    entry = create_entry(
        integration_session,
        submission.id,
    )

    entry.event_timestamp = timestamp

    integration_session.flush()
    integration_session.refresh(entry)

    assert entry.event_timestamp == timestamp
    assert entry.event_timestamp.tzinfo is not None


def test_nullable_metadata(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    entry = LogEntry(
        submission_id=submission.id,
        position=1,
        severity=LogSeverity.UNKNOWN,
        message="Unstructured diagnostic message.",
    )

    integration_session.add(entry)
    integration_session.flush()
    integration_session.refresh(entry)

    assert entry.event_timestamp is None
    assert entry.original_severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_invalid_database_log_format(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    with pytest.raises(DataError):
        with integration_session.begin_nested():
            integration_session.execute(
                text(
                    "UPDATE log_submissions "
                    "SET source_format = 'unsupported' "
                    "WHERE id = :id"
                ),
                {"id": submission.id},
            )


def test_invalid_database_log_severity(
    integration_session: Session,
    log_incident: Incident,
) -> None:
    submission = create_submission(
        integration_session,
        log_incident.id,
    )

    entry = create_entry(
        integration_session,
        submission.id,
    )

    with pytest.raises(DataError):
        with integration_session.begin_nested():
            integration_session.execute(
                text("UPDATE log_entries SET severity = 'unsupported' WHERE id = :id"),
                {"id": entry.id},
            )
