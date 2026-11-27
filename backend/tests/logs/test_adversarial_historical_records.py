from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from typing import Any, cast
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.logs.exceptions import LogPersistenceIntegrityError
from app.models.application_log import LogEntry, LogSubmission
from app.models.log_enums import LogFormat, LogSeverity
from app.repositories.application_log import ApplicationLogRepository
from app.services.log_query import LogQueryService

INCIDENT_ID = UUID("10000000-0000-4000-8000-000000000001")
SUBMISSION_ID = UUID("20000000-0000-4000-8000-000000000002")
ENTRY_ID = UUID("30000000-0000-4000-8000-000000000003")

CANARY = "SYNTHETIC_HISTORICAL_RECORD_CANARY"

INVALID_UUIDS = (
    None,
    CANARY,
    123,
    True,
    b"identifier",
)

INVALID_POSITIVE_VALUES = (
    None,
    True,
    False,
    1.0,
    1.5,
    "1",
    CANARY,
    0,
    -1,
)

INVALID_REDACTION_VALUES = (
    None,
    True,
    False,
    0.0,
    1.5,
    "0",
    CANARY,
    -1,
    2**31,
)

INVALID_TIMESTAMPS = (
    datetime(2026, 11, 24, 12, 0),
    date(2026, 11, 24),
    CANARY,
    123,
    True,
    b"timestamp",
)

INVALID_SUBMISSION_FIELDS = (
    tuple((field, value) for field in ("id", "incident_id") for value in INVALID_UUIDS)
    + tuple(
        ("source_format", value)
        for value in (
            None,
            "json",
            CANARY,
            LogSeverity.ERROR,
            True,
        )
    )
    + tuple(
        ("payload_bytes", value)
        for value in INVALID_POSITIVE_VALUES + (10485761, 2**31)
    )
    + tuple(
        ("entry_count", value) for value in INVALID_POSITIVE_VALUES + (10001, 2**31)
    )
    + tuple(("redaction_count", value) for value in INVALID_REDACTION_VALUES)
    + tuple(("created_at", value) for value in INVALID_TIMESTAMPS + (None,))
)

INVALID_ENTRY_FIELDS = (
    tuple(
        (field, value) for field in ("id", "submission_id") for value in INVALID_UUIDS
    )
    + tuple(("position", value) for value in INVALID_POSITIVE_VALUES + (10001, 2**31))
    + tuple(
        ("severity", value)
        for value in (
            None,
            "error",
            CANARY,
            LogFormat.JSON,
            True,
        )
    )
    + tuple(
        ("message", value)
        for value in (
            None,
            "",
            " ",
            "\t",
            "\r\n",
            " \t\r\n ",
            123,
            True,
            b"message",
        )
    )
    + tuple(("event_timestamp", value) for value in INVALID_TIMESTAMPS)
)


@pytest.fixture
def submission() -> LogSubmission:
    return LogSubmission(
        id=SUBMISSION_ID,
        incident_id=INCIDENT_ID,
        source_format=LogFormat.JSON,
        source_name="synthetic-service",
        payload_bytes=100,
        entry_count=1,
        redaction_count=0,
        created_at=datetime(2026, 11, 24, 12, 0, tzinfo=UTC),
    )


@pytest.fixture
def entry() -> LogEntry:
    return LogEntry(
        id=ENTRY_ID,
        submission_id=SUBMISSION_ID,
        position=1,
        severity=LogSeverity.ERROR,
        message="Database connection failed.",
        event_timestamp=datetime(2026, 11, 24, 12, 0, tzinfo=UTC),
    )


@pytest.fixture
def query(
    monkeypatch: pytest.MonkeyPatch,
    submission: LogSubmission,
    entry: LogEntry,
) -> LogQueryService:
    session = MagicMock(spec=Session)
    session.__enter__.return_value = session
    session.get.return_value = object()

    monkeypatch.setattr(
        ApplicationLogRepository,
        "get_by_id",
        MagicMock(return_value=submission),
    )

    monkeypatch.setattr(
        ApplicationLogRepository,
        "list_by_incident",
        MagicMock(return_value=[submission]),
    )

    monkeypatch.setattr(
        ApplicationLogRepository,
        "count_by_incident",
        MagicMock(return_value=1),
    )

    monkeypatch.setattr(
        ApplicationLogRepository,
        "get_entry",
        MagicMock(return_value=entry),
    )

    monkeypatch.setattr(
        ApplicationLogRepository,
        "list_entries",
        MagicMock(return_value=[entry]),
    )

    monkeypatch.setattr(
        ApplicationLogRepository,
        "count_entries",
        MagicMock(return_value=1),
    )

    settings = Settings(_env_file=None).model_copy(
        update={
            "log_max_entries": 10000,
            "log_max_payload_bytes": 10485760,
            "log_max_message_chars": 20000,
            "log_max_metadata_chars": 2000,
        }
    )

    return LogQueryService(
        lambda: session,
        settings,
    )


def invoke_query(
    query: LogQueryService,
    operation: str,
) -> Any:
    if operation == "get_submission":
        return query.get_submission(
            INCIDENT_ID,
            SUBMISSION_ID,
        )

    if operation == "list_submissions":
        return query.list_submissions(
            INCIDENT_ID,
        )

    if operation == "get_entry":
        return query.get_entry(
            INCIDENT_ID,
            SUBMISSION_ID,
            ENTRY_ID,
        )

    if operation == "list_entries":
        return query.list_entries(
            INCIDENT_ID,
            SUBMISSION_ID,
        )

    assert operation == "get_evidence"

    return query.get_evidence(
        INCIDENT_ID,
        SUBMISSION_ID,
    )


@pytest.mark.parametrize(
    "operation",
    (
        "get_submission",
        "list_submissions",
        "get_evidence",
    ),
)
@pytest.mark.parametrize(
    "field,value",
    INVALID_SUBMISSION_FIELDS,
)
def test_invalid_historical_submission_rejected(
    query: LogQueryService,
    submission: LogSubmission,
    operation: str,
    field: str,
    value: Any,
) -> None:
    setattr(submission, field, value)

    with pytest.raises(LogPersistenceIntegrityError) as captured:
        invoke_query(query, operation)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "operation",
    (
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
@pytest.mark.parametrize(
    "field,value",
    INVALID_ENTRY_FIELDS,
)
def test_invalid_historical_entry_rejected(
    query: LogQueryService,
    entry: LogEntry,
    operation: str,
    field: str,
    value: Any,
) -> None:
    setattr(entry, field, value)

    with pytest.raises(LogPersistenceIntegrityError) as captured:
        invoke_query(query, operation)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "operation",
    (
        "get_submission",
        "list_submissions",
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
def test_valid_historical_records_preserved(
    query: LogQueryService,
    operation: str,
) -> None:
    result = invoke_query(query, operation)

    if operation == "get_submission":
        assert result.id == SUBMISSION_ID
        assert result.entry_count == 1

    elif operation == "list_submissions":
        assert result.total == 1
        assert result.items[0].id == SUBMISSION_ID

    elif operation == "get_entry":
        assert result.id == ENTRY_ID
        assert result.message == "Database connection failed."

    elif operation == "list_entries":
        assert result.total == 1
        assert result.items[0].id == ENTRY_ID

    else:
        assert result.total_events == 1
        assert result.has_evidence


@pytest.mark.parametrize(
    "operation",
    (
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
def test_optional_historical_timestamp_preserved(
    query: LogQueryService,
    entry: LogEntry,
    operation: str,
) -> None:
    entry.event_timestamp = None

    result = invoke_query(query, operation)

    if operation == "get_entry":
        assert result.event_timestamp is None

    elif operation == "list_entries":
        assert result.items[0].event_timestamp is None

    else:
        assert result.events[0].event_timestamp is None


MISMATCHED_ID = UUID("40000000-0000-4000-8000-000000000004")


@pytest.mark.parametrize(
    "operation,field",
    (
        ("get_submission", "id"),
        ("get_submission", "incident_id"),
        ("list_submissions", "incident_id"),
        ("get_evidence", "id"),
        ("get_evidence", "incident_id"),
        ("get_entry", "id"),
        ("get_entry", "submission_id"),
        ("list_entries", "submission_id"),
        ("get_evidence", "submission_id"),
    ),
)
def test_mismatched_historical_identifier_rejected(
    query: LogQueryService,
    submission: LogSubmission,
    entry: LogEntry,
    operation: str,
    field: str,
) -> None:
    if (
        operation
        in {
            "get_submission",
            "list_submissions",
        }
        or field == "incident_id"
        or (operation == "get_evidence" and field == "id")
    ):
        setattr(submission, field, MISMATCHED_ID)
    else:
        setattr(entry, field, MISMATCHED_ID)

    with pytest.raises(LogPersistenceIntegrityError):
        invoke_query(query, operation)


@pytest.mark.parametrize(
    "operation",
    ("get_entry", "list_entries"),
)
@pytest.mark.parametrize(
    "field,value",
    INVALID_SUBMISSION_FIELDS,
)
def test_invalid_historical_parent_rejected(
    query: LogQueryService,
    submission: LogSubmission,
    operation: str,
    field: str,
    value: Any,
) -> None:
    setattr(submission, field, value)

    with pytest.raises(LogPersistenceIntegrityError) as captured:
        invoke_query(query, operation)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "operation",
    ("get_entry", "list_entries"),
)
@pytest.mark.parametrize(
    "field",
    ("id", "incident_id"),
)
def test_mismatched_historical_parent_rejected(
    query: LogQueryService,
    submission: LogSubmission,
    operation: str,
    field: str,
) -> None:
    setattr(submission, field, MISMATCHED_ID)

    with pytest.raises(LogPersistenceIntegrityError):
        invoke_query(query, operation)


@pytest.mark.parametrize(
    "operation",
    ("get_entry", "list_entries"),
)
@pytest.mark.parametrize(
    "position",
    (2, 100, 10000),
)
def test_entry_position_exceeds_parent_count(
    query: LogQueryService,
    entry: LogEntry,
    operation: str,
    position: int,
) -> None:
    entry.position = position

    with pytest.raises(LogPersistenceIntegrityError):
        invoke_query(query, operation)


@pytest.mark.parametrize(
    "field,value",
    INVALID_SUBMISSION_FIELDS,
)
def test_invalid_submission_prevents_extraction(
    query: LogQueryService,
    submission: LogSubmission,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: Any,
) -> None:
    setattr(submission, field, value)

    extractor = MagicMock()

    monkeypatch.setattr(
        query._extractor,
        "extract",
        extractor,
    )

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            INCIDENT_ID,
            SUBMISSION_ID,
        )

    extractor.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    INVALID_ENTRY_FIELDS,
)
def test_invalid_entry_prevents_extraction(
    query: LogQueryService,
    entry: LogEntry,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: Any,
) -> None:
    setattr(entry, field, value)

    extractor = MagicMock()

    monkeypatch.setattr(
        query._extractor,
        "extract",
        extractor,
    )

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            INCIDENT_ID,
            SUBMISSION_ID,
        )

    extractor.assert_not_called()


@pytest.mark.parametrize(
    "record_type,field",
    (
        ("submission", "id"),
        ("submission", "incident_id"),
        ("entry", "submission_id"),
    ),
)
def test_mismatched_identifier_prevents_extraction(
    query: LogQueryService,
    submission: LogSubmission,
    entry: LogEntry,
    monkeypatch: pytest.MonkeyPatch,
    record_type: str,
    field: str,
) -> None:
    record = submission if record_type == "submission" else entry

    setattr(record, field, MISMATCHED_ID)

    extractor = MagicMock()

    monkeypatch.setattr(
        query._extractor,
        "extract",
        extractor,
    )

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            INCIDENT_ID,
            SUBMISSION_ID,
        )

    extractor.assert_not_called()


@pytest.mark.parametrize(
    "operation",
    ("get_entry", "list_entries", "get_evidence"),
)
def test_valid_nonfirst_entry_position(
    query: LogQueryService,
    submission: LogSubmission,
    entry: LogEntry,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    submission.entry_count = 2
    entry.position = 2

    if operation == "get_evidence":
        first_entry = LogEntry(
            id=MISMATCHED_ID,
            submission_id=SUBMISSION_ID,
            position=1,
            severity=LogSeverity.INFO,
            message="Workflow started.",
        )

        monkeypatch.setattr(
            ApplicationLogRepository,
            "list_entries",
            MagicMock(return_value=[first_entry, entry]),
        )

    result = invoke_query(query, operation)

    if operation == "get_entry":
        assert result.position == 2
    elif operation == "list_entries":
        assert result.items[0].position == 2
    else:
        assert result.total_events == 2


class InvalidOffsetTimezone(tzinfo):
    def __init__(self, behavior: str) -> None:
        self.behavior = behavior

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        if self.behavior == "none":
            return None

        if self.behavior == "type_error":
            raise TypeError(CANARY)

        if self.behavior == "value_error":
            raise ValueError(CANARY)

        if self.behavior == "overflow_error":
            raise OverflowError(CANARY)

        if self.behavior == "invalid_type":
            return cast(timedelta, CANARY)

        assert self.behavior == "invalid_range"

        return timedelta(hours=24)

    def dst(self, dt: datetime | None) -> timedelta | None:
        raise NotImplementedError

    def tzname(self, dt: datetime | None) -> str | None:
        raise NotImplementedError


INVALID_TIMEZONE_BEHAVIORS = (
    "none",
    "type_error",
    "value_error",
    "overflow_error",
    "invalid_type",
    "invalid_range",
)


@pytest.mark.parametrize(
    "operation",
    (
        "get_submission",
        "list_submissions",
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
@pytest.mark.parametrize(
    "behavior",
    INVALID_TIMEZONE_BEHAVIORS,
)
def test_invalid_creation_timezone_rejected(
    query: LogQueryService,
    submission: LogSubmission,
    operation: str,
    behavior: str,
) -> None:
    submission.created_at = datetime(
        2026,
        11,
        24,
        12,
        0,
        tzinfo=InvalidOffsetTimezone(behavior),
    )

    with pytest.raises(LogPersistenceIntegrityError) as captured:
        invoke_query(query, operation)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "operation",
    (
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
@pytest.mark.parametrize(
    "behavior",
    INVALID_TIMEZONE_BEHAVIORS,
)
def test_invalid_event_timezone_rejected(
    query: LogQueryService,
    entry: LogEntry,
    operation: str,
    behavior: str,
) -> None:
    entry.event_timestamp = datetime(
        2026,
        11,
        24,
        12,
        0,
        tzinfo=InvalidOffsetTimezone(behavior),
    )

    with pytest.raises(LogPersistenceIntegrityError) as captured:
        invoke_query(query, operation)

    assert CANARY not in str(captured.value)


UTC_OVERFLOW_TIMESTAMPS = (
    datetime.min.replace(
        tzinfo=timezone(timedelta(hours=1)),
    ),
    datetime.max.replace(
        tzinfo=timezone(timedelta(hours=-1)),
    ),
)


@pytest.mark.parametrize(
    "operation",
    (
        "get_submission",
        "list_submissions",
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
@pytest.mark.parametrize(
    "timestamp",
    UTC_OVERFLOW_TIMESTAMPS,
)
def test_creation_timestamp_utc_overflow_rejected(
    query: LogQueryService,
    submission: LogSubmission,
    operation: str,
    timestamp: datetime,
) -> None:
    submission.created_at = timestamp

    with pytest.raises(LogPersistenceIntegrityError):
        invoke_query(query, operation)


@pytest.mark.parametrize(
    "operation",
    (
        "get_entry",
        "list_entries",
        "get_evidence",
    ),
)
@pytest.mark.parametrize(
    "timestamp",
    UTC_OVERFLOW_TIMESTAMPS,
)
def test_event_timestamp_utc_overflow_rejected(
    query: LogQueryService,
    entry: LogEntry,
    operation: str,
    timestamp: datetime,
) -> None:
    entry.event_timestamp = timestamp

    with pytest.raises(LogPersistenceIntegrityError):
        invoke_query(query, operation)


@pytest.mark.parametrize(
    "offset_minutes",
    (-840, -300, 0, 330, 840),
)
def test_valid_timezone_offsets_preserved(
    query: LogQueryService,
    submission: LogSubmission,
    entry: LogEntry,
    offset_minutes: int,
) -> None:
    timestamp = datetime(
        2026,
        11,
        24,
        12,
        0,
        tzinfo=timezone(timedelta(minutes=offset_minutes)),
    )

    submission.created_at = timestamp
    entry.event_timestamp = timestamp

    stored_submission = query.get_submission(
        INCIDENT_ID,
        SUBMISSION_ID,
    )

    stored_entry = query.get_entry(
        INCIDENT_ID,
        SUBMISSION_ID,
        ENTRY_ID,
    )

    evidence = query.get_evidence(
        INCIDENT_ID,
        SUBMISSION_ID,
    )

    assert stored_submission.created_at == timestamp

    assert stored_entry.event_timestamp == timestamp

    assert evidence.events[0].event_timestamp == (timestamp.astimezone(UTC).isoformat())


@pytest.mark.parametrize(
    "behavior",
    INVALID_TIMEZONE_BEHAVIORS,
)
def test_invalid_timezone_prevents_extraction(
    query: LogQueryService,
    entry: LogEntry,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
) -> None:
    entry.event_timestamp = datetime(
        2026,
        11,
        24,
        12,
        0,
        tzinfo=InvalidOffsetTimezone(behavior),
    )

    extractor = MagicMock()

    monkeypatch.setattr(
        query._extractor,
        "extract",
        extractor,
    )

    with pytest.raises(LogPersistenceIntegrityError):
        query.get_evidence(
            INCIDENT_ID,
            SUBMISSION_ID,
        )

    extractor.assert_not_called()
