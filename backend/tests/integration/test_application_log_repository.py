from dataclasses import replace
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.logs.contracts import NormalizedLog
from app.logs.normalizer import LogNormalizer
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.logs.sanitizer import LogSanitizer
from app.models.incident import Incident
from app.models.log_enums import LogFormat, LogSeverity
from app.repositories.application_log import ApplicationLogRepository

CANARY = "SYNTHETIC_SECRET_CANARY"


@pytest.fixture
def repository(
    integration_session: Session,
) -> ApplicationLogRepository:
    return ApplicationLogRepository(integration_session)


@pytest.fixture
def incident(
    integration_session: Session,
) -> Incident:
    record = Incident(
        title="Log repository integration test",
        description="Synthetic application log incident.",
    )

    integration_session.add(record)
    integration_session.flush()

    return record


@pytest.fixture
def other_incident(
    integration_session: Session,
) -> Incident:
    record = Incident(
        title="Separate log repository incident",
        description="Synthetic isolation test.",
    )

    integration_session.add(record)
    integration_session.flush()

    return record


@pytest.fixture
def sanitized_log() -> SanitizedLog:
    settings = Settings(_env_file=None)

    payload = (
        b'[{"severity":"INFO","message":"Workflow started"},'
        b'{"severity":"ERROR",'
        b'"message":"Authentication failed '
        b'password=SYNTHETIC_SECRET_CANARY",'
        b'"timestamp":"2026-11-24T10:30:00-05:00",'
        b'"service_name":"ticketing",'
        b'"exception":"Synthetic exception",'
        b'"error_code":"TK-ERR",'
        b'"correlation_id":"TXN-123"},'
        b'{"severity":"CRITICAL",'
        b'"message":"Invalid signature"}]'
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.JSON,
    )

    return LogSanitizer(settings).sanitize(normalized)


def test_create_submission(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    result = repository.create(
        incident.id,
        sanitized_log,
        source_name="ticketing-service",
    )

    assert result.id is not None
    assert result.incident_id == incident.id
    assert result.source_format == LogFormat.JSON
    assert result.source_name == "ticketing-service"
    assert result.payload_bytes == sanitized_log.payload_bytes
    assert result.entry_count == 3
    assert result.redaction_count == sanitized_log.redaction_count
    assert result.created_at is not None


def test_persist_all_events(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    integration_session: Session,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    integration_session.expire_all()

    entries = repository.list_entries(
        incident.id,
        submission.id,
    )

    assert len(entries) == 3

    assert [entry.position for entry in entries] == [1, 2, 3]

    assert [entry.severity for entry in entries] == [
        LogSeverity.INFO,
        LogSeverity.ERROR,
        LogSeverity.CRITICAL,
    ]

    for expected, actual in zip(
        sanitized_log.entries,
        entries,
        strict=True,
    ):
        assert actual.submission_id == submission.id
        assert actual.position == expected.position
        assert actual.severity == expected.severity
        assert actual.message == expected.message
        assert actual.event_timestamp == expected.event_timestamp
        assert actual.original_severity == expected.original_severity
        assert actual.service_name == expected.service_name
        assert actual.exception == expected.exception
        assert actual.error_code == expected.error_code
        assert actual.correlation_id == expected.correlation_id


def test_timestamp_persisted_in_utc(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    entries = repository.list_entries(
        incident.id,
        submission.id,
    )

    assert entries[1].event_timestamp == datetime(2026, 11, 24, 15, 30, tzinfo=UTC)


def test_recognized_credentials_not_persisted(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    integration_session: Session,
) -> None:
    settings = Settings(_env_file=None)

    source_name, source_count = LogSanitizer(settings).sanitize_source_name(
        f"password={CANARY}"
    )

    submission = repository.create(
        incident.id,
        sanitized_log,
        source_name=source_name,
        source_redaction_count=source_count,
    )

    integration_session.expire_all()

    stored = repository.get_by_id(
        incident.id,
        submission.id,
    )

    assert stored is not None
    assert stored.source_name is not None
    assert CANARY not in stored.source_name

    assert stored.redaction_count == (sanitized_log.redaction_count + source_count)

    entries = repository.list_entries(
        incident.id,
        submission.id,
    )

    for entry in entries:
        values = (
            entry.message,
            entry.exception,
            entry.original_severity,
            entry.service_name,
            entry.error_code,
            entry.correlation_id,
        )

        assert all(CANARY not in (value or "") for value in values)


def test_get_submission(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    result = repository.get_by_id(
        incident.id,
        submission.id,
    )

    assert result is not None
    assert result.id == submission.id


def test_missing_submission(
    repository: ApplicationLogRepository,
    incident: Incident,
) -> None:
    assert (
        repository.get_by_id(
            incident.id,
            uuid4(),
        )
        is None
    )


def test_submission_incident_isolation(
    repository: ApplicationLogRepository,
    incident: Incident,
    other_incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    assert (
        repository.get_by_id(
            other_incident.id,
            submission.id,
        )
        is None
    )


def test_list_and_count_submissions(
    repository: ApplicationLogRepository,
    incident: Incident,
    other_incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    first = repository.create(
        incident.id,
        sanitized_log,
    )

    second = repository.create(
        incident.id,
        sanitized_log,
    )

    unrelated = repository.create(
        other_incident.id,
        sanitized_log,
    )

    results = repository.list_by_incident(incident.id)

    assert {record.id for record in results} == {
        first.id,
        second.id,
    }

    assert unrelated.id not in {record.id for record in results}

    assert repository.count_by_incident(incident.id) == 2

    assert repository.count_by_incident(other_incident.id) == 1


def test_submission_pagination(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    for _ in range(5):
        repository.create(
            incident.id,
            sanitized_log,
        )

    complete = repository.list_by_incident(incident.id)

    first = repository.list_by_incident(
        incident.id,
        offset=0,
        limit=2,
    )

    second = repository.list_by_incident(
        incident.id,
        offset=2,
        limit=2,
    )

    third = repository.list_by_incident(
        incident.id,
        offset=4,
        limit=2,
    )

    assert len(first) == 2
    assert len(second) == 2
    assert len(third) == 1

    assert [item.id for item in first + second + third] == [
        item.id for item in complete
    ]


def test_empty_submission_queries(
    repository: ApplicationLogRepository,
    incident: Incident,
) -> None:
    assert repository.list_by_incident(incident.id) == []

    assert repository.count_by_incident(incident.id) == 0


def test_get_individual_entry(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    expected = repository.list_entries(
        incident.id,
        submission.id,
    )[1]

    result = repository.get_entry(
        incident.id,
        submission.id,
        expected.id,
    )

    assert result is not None
    assert result.id == expected.id
    assert result.position == 2


def test_missing_entry(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    assert (
        repository.get_entry(
            incident.id,
            submission.id,
            uuid4(),
        )
        is None
    )


def test_entry_incident_isolation(
    repository: ApplicationLogRepository,
    incident: Incident,
    other_incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    entry = repository.list_entries(
        incident.id,
        submission.id,
    )[0]

    assert (
        repository.get_entry(
            other_incident.id,
            submission.id,
            entry.id,
        )
        is None
    )

    assert (
        repository.list_entries(
            other_incident.id,
            submission.id,
        )
        == []
    )

    assert (
        repository.count_entries(
            other_incident.id,
            submission.id,
        )
        == 0
    )


def test_entry_submission_isolation(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    first = repository.create(
        incident.id,
        sanitized_log,
    )

    second = repository.create(
        incident.id,
        sanitized_log,
    )

    entry = repository.list_entries(
        incident.id,
        first.id,
    )[0]

    assert (
        repository.get_entry(
            incident.id,
            second.id,
            entry.id,
        )
        is None
    )


@pytest.mark.parametrize(
    ("severity", "expected_count"),
    [
        (LogSeverity.INFO, 1),
        (LogSeverity.ERROR, 1),
        (LogSeverity.CRITICAL, 1),
        (LogSeverity.WARNING, 0),
        (LogSeverity.DEBUG, 0),
        (LogSeverity.TRACE, 0),
        (LogSeverity.UNKNOWN, 0),
    ],
)
def test_severity_filtering(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    severity: LogSeverity,
    expected_count: int,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    entries = repository.list_entries(
        incident.id,
        submission.id,
        severity=severity,
    )

    count = repository.count_entries(
        incident.id,
        submission.id,
        severity=severity,
    )

    assert len(entries) == expected_count
    assert count == expected_count

    assert all(entry.severity == severity for entry in entries)


def test_unfiltered_entry_count(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    assert (
        repository.count_entries(
            incident.id,
            submission.id,
        )
        == 3
    )


def test_entry_pagination(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    first = repository.list_entries(
        incident.id,
        submission.id,
        offset=0,
        limit=2,
    )

    second = repository.list_entries(
        incident.id,
        submission.id,
        offset=2,
        limit=2,
    )

    assert [entry.position for entry in first] == [1, 2]

    assert [entry.position for entry in second] == [3]

    assert (
        repository.list_entries(
            incident.id,
            submission.id,
            offset=3,
            limit=2,
        )
        == []
    )


def test_missing_submission_entry_queries(
    repository: ApplicationLogRepository,
    incident: Incident,
) -> None:
    missing_id = uuid4()

    assert (
        repository.list_entries(
            incident.id,
            missing_id,
        )
        == []
    )

    assert (
        repository.count_entries(
            incident.id,
            missing_id,
        )
        == 0
    )


def test_delete_submission(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    submission_id = submission.id

    assert (
        repository.delete(
            incident.id,
            submission_id,
        )
        is True
    )

    assert (
        repository.get_by_id(
            incident.id,
            submission_id,
        )
        is None
    )

    assert (
        repository.count_entries(
            incident.id,
            submission_id,
        )
        == 0
    )

    assert repository.count_by_incident(incident.id) == 0


def test_delete_missing_submission(
    repository: ApplicationLogRepository,
    incident: Incident,
) -> None:
    assert (
        repository.delete(
            incident.id,
            uuid4(),
        )
        is False
    )


def test_delete_does_not_cross_incidents(
    repository: ApplicationLogRepository,
    incident: Incident,
    other_incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    assert (
        repository.delete(
            other_incident.id,
            submission.id,
        )
        is False
    )

    assert (
        repository.get_by_id(
            incident.id,
            submission.id,
        )
        is not None
    )

    assert (
        repository.count_entries(
            incident.id,
            submission.id,
        )
        == 3
    )


def test_delete_preserves_other_submissions(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    first = repository.create(
        incident.id,
        sanitized_log,
    )

    second = repository.create(
        incident.id,
        sanitized_log,
    )

    assert (
        repository.delete(
            incident.id,
            first.id,
        )
        is True
    )

    assert (
        repository.get_by_id(
            incident.id,
            second.id,
        )
        is not None
    )

    assert (
        repository.count_entries(
            incident.id,
            second.id,
        )
        == 3
    )


def test_unsanitized_contract_rejected(
    repository: ApplicationLogRepository,
    incident: Incident,
) -> None:
    normalized = NormalizedLog(
        source_format=LogFormat.JSON,
        payload_bytes=100,
        entries=(),
    )

    with pytest.raises(
        TypeError,
        match="requires sanitized records",
    ):
        repository.create(
            incident.id,
            cast(SanitizedLog, normalized),
        )


@pytest.mark.parametrize(
    "payload_bytes",
    [0, -1],
)
def test_invalid_payload_size_rejected(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    payload_bytes: int,
) -> None:
    invalid = replace(
        sanitized_log,
        payload_bytes=payload_bytes,
    )

    with pytest.raises(
        ValueError,
        match="positive size and entry count",
    ):
        repository.create(
            incident.id,
            invalid,
        )


def test_empty_submission_rejected(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    invalid = replace(
        sanitized_log,
        entries=(),
    )

    with pytest.raises(ValueError):
        repository.create(
            incident.id,
            invalid,
        )


def test_negative_source_redaction_count(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    with pytest.raises(
        ValueError,
        match="Source redaction count",
    ):
        repository.create(
            incident.id,
            sanitized_log,
            source_redaction_count=-1,
        )


@pytest.mark.parametrize(
    "position",
    [0, -1, 2],
)
def test_invalid_event_position_rejected(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    position: int,
) -> None:
    entry = replace(
        sanitized_log.entries[0],
        position=position,
    )

    invalid = replace(
        sanitized_log,
        entries=(entry,),
    )

    with pytest.raises(
        ValueError,
        match="sequential",
    ):
        repository.create(
            incident.id,
            invalid,
        )


def test_negative_entry_redaction_count(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    entry = replace(
        sanitized_log.entries[0],
        redaction_count=-1,
    )

    invalid = replace(
        sanitized_log,
        entries=(entry,),
    )

    with pytest.raises(
        ValueError,
        match="Entry redaction count",
    ):
        repository.create(
            incident.id,
            invalid,
        )


@pytest.mark.parametrize(
    "message",
    ["", " ", "\t\r\n"],
)
def test_empty_event_message_rejected(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    message: str,
) -> None:
    entry = SanitizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message=message,
    )

    invalid = replace(
        sanitized_log,
        entries=(entry,),
    )

    with pytest.raises(
        ValueError,
        match="nonempty message",
    ):
        repository.create(
            incident.id,
            invalid,
        )


def test_invalid_submission_creates_no_records(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    invalid_entry = replace(
        sanitized_log.entries[1],
        message=" ",
    )

    invalid = replace(
        sanitized_log,
        entries=(
            sanitized_log.entries[0],
            invalid_entry,
        ),
    )

    with pytest.raises(ValueError):
        repository.create(
            incident.id,
            invalid,
        )

    assert repository.count_by_incident(incident.id) == 0


def test_caller_controls_transaction(
    repository: ApplicationLogRepository,
    incident: Incident,
    sanitized_log: SanitizedLog,
    integration_session: Session,
) -> None:
    transaction = integration_session.begin_nested()

    submission = repository.create(
        incident.id,
        sanitized_log,
    )

    submission_id = submission.id

    assert (
        repository.count_entries(
            incident.id,
            submission_id,
        )
        == 3
    )

    transaction.rollback()

    assert (
        repository.get_by_id(
            incident.id,
            submission_id,
        )
        is None
    )

    assert repository.count_by_incident(incident.id) == 0


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
def test_end_to_end_format_persistence(
    repository: ApplicationLogRepository,
    incident: Incident,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    settings = Settings(_env_file=None)

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    submission = repository.create(
        incident.id,
        sanitized,
    )

    entries = repository.list_entries(
        incident.id,
        submission.id,
    )

    assert submission.source_format == source_format
    assert submission.payload_bytes == len(payload)
    assert submission.entry_count == 1
    assert len(entries) == 1

    assert entries[0].position == 1
    assert entries[0].severity == LogSeverity.ERROR
    assert entries[0].message == "Database connection failed"


@pytest.mark.parametrize(
    "scenario",
    (
        "null_message",
        "boolean_position",
        "floating_position",
        "invalid_severity",
        "naive_timestamp",
        "invalid_timestamp",
        "oversized_metadata",
        "oversized_message",
        "invalid_entry_count",
        "combined_overflow",
        "oversized_payload",
        "invalid_format",
    ),
)
def test_adversarial_rejection_preserves_transaction(
    repository: ApplicationLogRepository,
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
    scenario: str,
) -> None:
    incident_id = incident.id

    entries = list(sanitized_log.entries)

    source_count = 0

    if scenario == "null_message":
        entries[-1] = replace(
            entries[-1],
            message=cast(str, None),
        )
    elif scenario == "boolean_position":
        entries[0] = replace(entries[0], position=True)
    elif scenario == "floating_position":
        entries[0] = replace(
            entries[0],
            position=cast(int, 1.0),
        )
    elif scenario == "invalid_severity":
        entries[-1] = replace(
            entries[-1],
            severity=cast(LogSeverity, "error"),
        )
    elif scenario == "naive_timestamp":
        entries[-1] = replace(
            entries[-1],
            event_timestamp=datetime(2026, 11, 24, 12, 0),
        )
    elif scenario == "invalid_timestamp":
        entries[-1] = replace(
            entries[-1],
            event_timestamp=cast(datetime, "invalid"),
        )
    elif scenario == "oversized_metadata":
        entries[-1] = replace(
            entries[-1],
            service_name="x" * 2001,
        )
    elif scenario == "oversized_message":
        entries[-1] = replace(
            entries[-1],
            message="x" * 20001,
        )
    elif scenario == "invalid_entry_count":
        entries = []
    elif scenario == "combined_overflow":
        entries[0] = replace(
            entries[0],
            redaction_count=2**31 - 1,
        )
        source_count = 1

    invalid = replace(
        sanitized_log,
        entries=tuple(entries),
    )

    if scenario == "oversized_payload":
        invalid = replace(
            invalid,
            payload_bytes=10485761,
        )
    elif scenario == "invalid_format":
        invalid = replace(
            invalid,
            source_format=cast(LogFormat, "json"),
        )

    before = repository.count_by_incident(incident_id)

    assert before == 0

    with pytest.raises(ValueError):
        repository.create(
            incident_id,
            invalid,
            source_redaction_count=source_count,
        )

    assert integration_session.is_active
    assert not integration_session.new
    assert not integration_session.dirty
    assert not integration_session.deleted

    assert repository.count_by_incident(incident_id) == before

    valid = repository.create(
        incident_id,
        sanitized_log,
    )

    assert repository.count_by_incident(incident_id) == 1

    assert (
        repository.count_entries(
            incident_id,
            valid.id,
        )
        == sanitized_log.entry_count
    )


def test_maximum_persistence_values_round_trip(
    repository: ApplicationLogRepository,
    integration_session: Session,
    incident: Incident,
    sanitized_log: SanitizedLog,
) -> None:
    entry = replace(
        sanitized_log.entries[0],
        position=1,
        message="x" * 20000,
        exception="y" * 20000,
        service_name="s" * 2000,
        original_severity="o" * 2000,
        error_code="e" * 2000,
        correlation_id="c" * 2000,
        redaction_count=2**31 - 2,
    )

    log = replace(
        sanitized_log,
        payload_bytes=10485760,
        entries=(entry,),
    )

    result = repository.create(
        incident.id,
        log,
        source_name="n" * 2000,
        source_redaction_count=1,
    )

    submission_id = result.id

    integration_session.expire_all()

    stored = repository.get_by_id(
        incident.id,
        submission_id,
    )

    assert stored is not None
    assert stored.payload_bytes == 10485760
    assert stored.redaction_count == 2**31 - 1
    assert stored.source_name == "n" * 2000
    assert stored.entry_count == 1

    entries = repository.list_entries(
        incident.id,
        submission_id,
    )

    assert len(entries) == 1

    record = entries[0]

    assert record.message == entry.message
    assert record.exception == entry.exception
    assert record.service_name == entry.service_name
    assert record.original_severity == entry.original_severity
    assert record.error_code == entry.error_code
    assert record.correlation_id == entry.correlation_id
