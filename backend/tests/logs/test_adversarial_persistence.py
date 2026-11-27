from dataclasses import replace
from dataclasses import replace as _replace
from datetime import UTC, date, datetime, timedelta, timezone
from datetime import timedelta as _timedelta
from datetime import timezone as _timezone
from datetime import tzinfo as _tzinfo
from typing import Any, cast
from unittest.mock import MagicMock
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.models.log_enums import LogFormat, LogSeverity
from app.repositories.application_log import (
    ApplicationLogRepository,
)

INCIDENT_ID = UUID("10000000-0000-4000-8000-000000000001")
CANARY = "SYNTHETIC_PERSISTENCE_SECURITY_CANARY"

INVALID_POSITIVE_INTEGERS: tuple[object, ...] = (
    None,
    True,
    False,
    1.0,
    1.5,
    "1",
    CANARY,
    b"1",
    [],
    {},
    0,
    -1,
)

INVALID_NONNEGATIVE_INTEGERS: tuple[object, ...] = (
    None,
    True,
    False,
    0.0,
    1.5,
    "0",
    CANARY,
    b"0",
    [],
    {},
    -1,
    -(2**31),
    2**31,
    2**63,
)

INVALID_MESSAGES: tuple[object, ...] = (
    None,
    "",
    " ",
    "\t",
    "\r\n",
    " \t\r\n ",
    123,
    True,
    b"message",
    [],
    {},
)

INVALID_FORMATS: tuple[object, ...] = (
    None,
    "json",
    "text",
    "xml",
    "unsupported",
    CANARY,
    1,
    True,
    b"json",
    LogSeverity.ERROR,
    [],
    {},
)

INVALID_SEVERITIES: tuple[object, ...] = (
    None,
    "error",
    "info",
    "unknown",
    "unsupported",
    CANARY,
    1,
    True,
    b"error",
    LogFormat.JSON,
    [],
    {},
)

INVALID_TIMESTAMPS: tuple[object, ...] = (
    datetime(2026, 11, 24, 12, 0),
    date(2026, 11, 24),
    "2026-11-24T12:00:00Z",
    CANARY,
    123,
    True,
    b"timestamp",
    [],
    {},
)

INVALID_INCIDENT_IDS: tuple[object, ...] = (
    None,
    str(INCIDENT_ID),
    CANARY,
    1,
    True,
    b"incident",
    [],
    {},
)


@pytest.fixture
def session() -> MagicMock:
    return MagicMock(spec=Session)


@pytest.fixture
def repository(
    session: MagicMock,
) -> ApplicationLogRepository:
    return ApplicationLogRepository(session)


@pytest.fixture
def valid_entry() -> SanitizedLogEntry:
    return SanitizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message="Synthetic diagnostic failure.",
        event_timestamp=datetime(2026, 11, 24, 12, 0, tzinfo=UTC),
    )


@pytest.fixture
def valid_log(
    valid_entry: SanitizedLogEntry,
) -> SanitizedLog:
    return SanitizedLog(
        source_format=LogFormat.JSON,
        payload_bytes=100,
        entries=(valid_entry,),
    )


@pytest.mark.parametrize("value", INVALID_MESSAGES)
def test_invalid_required_message_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    value: Any,
) -> None:
    entry = replace(valid_entry, message=value)
    log = replace(valid_log, entries=(entry,))

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "value",
    INVALID_POSITIVE_INTEGERS + (10485761, 2**31, 2**63),
)
def test_invalid_payload_size_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    value: Any,
) -> None:
    log = replace(valid_log, payload_bytes=value)

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "value",
    INVALID_POSITIVE_INTEGERS + (2, 10001, 2**31),
)
def test_invalid_position_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    value: Any,
) -> None:
    entry = replace(valid_entry, position=value)
    log = replace(valid_log, entries=(entry,))

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "value",
    INVALID_NONNEGATIVE_INTEGERS,
)
def test_invalid_source_redaction_count_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    value: Any,
) -> None:
    with pytest.raises(ValueError) as captured:
        repository.create(
            INCIDENT_ID,
            valid_log,
            source_redaction_count=value,
        )

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "value",
    INVALID_NONNEGATIVE_INTEGERS,
)
def test_invalid_entry_redaction_count_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    value: Any,
) -> None:
    entry = replace(
        valid_entry,
        redaction_count=value,
    )

    log = replace(valid_log, entries=(entry,))

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize("value", INVALID_FORMATS)
def test_invalid_source_format_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    value: Any,
) -> None:
    log = replace(valid_log, source_format=value)

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize("value", INVALID_SEVERITIES)
def test_invalid_severity_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    value: Any,
) -> None:
    entry = replace(valid_entry, severity=value)
    log = replace(valid_log, entries=(entry,))

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize("value", INVALID_TIMESTAMPS)
def test_invalid_timestamp_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    value: Any,
) -> None:
    entry = replace(
        valid_entry,
        event_timestamp=value,
    )

    log = replace(valid_log, entries=(entry,))

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize("value", INVALID_INCIDENT_IDS)
def test_invalid_incident_id_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    value: Any,
) -> None:
    with pytest.raises(ValueError) as captured:
        repository.create(value, valid_log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "value",
    (None, [], {}, "", 1, True, b"entries", ()),
)
def test_invalid_entry_collection_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    value: Any,
) -> None:
    log = replace(valid_log, entries=value)

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "value",
    (None, 1, True, CANARY, {}, [], b"entry"),
)
def test_invalid_entry_instance_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    value: Any,
) -> None:
    log = replace(valid_log, entries=(value,))

    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)

    assert CANARY not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "field",
    (
        "source_name",
        "original_severity",
        "service_name",
        "error_code",
        "correlation_id",
        "message",
        "exception",
    ),
)
def test_oversized_persistence_text_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    field: str,
) -> None:
    limit = 20000 if field in {"message", "exception"} else 2000

    value = "x" * (limit + 1)

    with pytest.raises(ValueError):
        if field == "source_name":
            repository.create(
                INCIDENT_ID,
                valid_log,
                source_name=value,
            )
        else:
            entry = replace(valid_entry, **cast(dict[str, Any], {field: value}))

            log = replace(valid_log, entries=(entry,))

            repository.create(INCIDENT_ID, log)

    assert session.mock_calls == []


@pytest.mark.parametrize(
    "entry_count,source_count",
    (
        (2**31 - 1, 1),
        (2**31 - 2, 2),
        (2**31 - 1, 2**31 - 1),
    ),
)
def test_combined_redaction_overflow_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    entry_count: int,
    source_count: int,
) -> None:
    entry = replace(
        valid_entry,
        redaction_count=entry_count,
    )

    log = replace(valid_log, entries=(entry,))

    with pytest.raises(ValueError):
        repository.create(
            INCIDENT_ID,
            log,
            source_redaction_count=source_count,
        )

    assert session.mock_calls == []


@pytest.mark.parametrize(
    "field,value",
    (
        ("message", None),
        ("severity", "error"),
        ("position", 3),
        ("redaction_count", True),
        ("event_timestamp", "invalid"),
        ("service_name", "x" * 2001),
    ),
)
def test_invalid_later_entry_prevents_partial_persistence(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    field: str,
    value: Any,
) -> None:
    second = replace(valid_entry, position=2)

    second = replace(second, **{field: value})

    log = replace(
        valid_log,
        entries=(valid_entry, second),
    )

    with pytest.raises(ValueError):
        repository.create(INCIDENT_ID, log)

    assert session.mock_calls == []


@pytest.mark.parametrize(
    "source_format",
    tuple(LogFormat),
)
@pytest.mark.parametrize(
    "severity",
    tuple(LogSeverity),
)
def test_valid_format_and_severity_preserved(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    source_format: LogFormat,
    severity: LogSeverity,
) -> None:
    entry = replace(valid_entry, severity=severity)

    log = replace(
        valid_log,
        source_format=source_format,
        entries=(entry,),
    )

    submission = repository.create(INCIDENT_ID, log)

    assert submission.source_format == source_format
    assert submission.entry_count == 1

    session.add.assert_called_once()
    session.add_all.assert_called_once()

    stored_entries = session.add_all.call_args.args[0]

    assert stored_entries[0].severity == severity


@pytest.mark.parametrize(
    "timestamp",
    (
        None,
        datetime(2026, 11, 24, 12, 0, tzinfo=UTC),
        datetime(
            2026,
            11,
            24,
            12,
            0,
            tzinfo=timezone(timedelta(hours=-5)),
        ),
    ),
)
def test_valid_optional_timestamp_preserved(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    timestamp: datetime | None,
) -> None:
    entry = replace(
        valid_entry,
        event_timestamp=timestamp,
    )

    log = replace(valid_log, entries=(entry,))

    repository.create(INCIDENT_ID, log)

    stored_entries = session.add_all.call_args.args[0]

    assert stored_entries[0].event_timestamp == timestamp


@pytest.mark.parametrize("size", (1, 10485759, 10485760))
def test_valid_payload_size_boundaries(
    repository: ApplicationLogRepository,
    valid_log: SanitizedLog,
    size: int,
) -> None:
    log = replace(valid_log, payload_bytes=size)

    result = repository.create(INCIDENT_ID, log)

    assert result.payload_bytes == size


@pytest.mark.parametrize("count", (1, 9999, 10000))
def test_valid_entry_count_boundaries(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    count: int,
) -> None:
    entries = tuple(
        replace(valid_entry, position=position) for position in range(1, count + 1)
    )

    log = replace(valid_log, entries=entries)

    result = repository.create(INCIDENT_ID, log)

    assert result.entry_count == count

    stored = session.add_all.call_args.args[0]

    assert len(stored) == count
    assert stored[0].position == 1
    assert stored[-1].position == count


@pytest.mark.parametrize("count", (10001, 10002))
def test_excessive_entry_count_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    count: int,
) -> None:
    entries = tuple(
        replace(valid_entry, position=position) for position in range(1, count + 1)
    )

    log = replace(valid_log, entries=entries)

    with pytest.raises(ValueError):
        repository.create(INCIDENT_ID, log)

    assert session.mock_calls == []


@pytest.mark.parametrize(
    "field",
    (
        "source_name",
        "original_severity",
        "service_name",
        "error_code",
        "correlation_id",
        "message",
        "exception",
    ),
)
@pytest.mark.parametrize("difference", (-1, 0))
def test_valid_text_length_boundaries(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    field: str,
    difference: int,
) -> None:
    limit = 20000 if field in {"message", "exception"} else 2000

    value = "x" * (limit + difference)

    if field == "source_name":
        result = repository.create(
            INCIDENT_ID,
            valid_log,
            source_name=value,
        )

        assert result.source_name == value
    else:
        entry = replace(valid_entry, **cast(dict[str, Any], {field: value}))

        log = replace(valid_log, entries=(entry,))

        repository.create(INCIDENT_ID, log)

        stored = session.add_all.call_args.args[0]

        assert getattr(stored[0], field) == value


@pytest.mark.parametrize(
    "entry_count,source_count",
    (
        (0, 0),
        (1, 0),
        (0, 1),
        (2**31 - 1, 0),
        (0, 2**31 - 1),
        (2**31 - 2, 1),
    ),
)
def test_valid_redaction_count_boundaries(
    repository: ApplicationLogRepository,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    entry_count: int,
    source_count: int,
) -> None:
    entry = replace(
        valid_entry,
        redaction_count=entry_count,
    )

    log = replace(valid_log, entries=(entry,))

    result = repository.create(
        INCIDENT_ID,
        log,
        source_redaction_count=source_count,
    )

    assert result.redaction_count == (entry_count + source_count)


@pytest.mark.parametrize(
    "first_count,second_count,source_count",
    (
        (2**31 - 1, 1, 0),
        (2**31 - 2, 1, 1),
        (2**30, 2**30, 0),
    ),
)
def test_multiple_entry_redaction_overflow_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
    first_count: int,
    second_count: int,
    source_count: int,
) -> None:
    first = replace(
        valid_entry,
        redaction_count=first_count,
    )

    second = replace(
        valid_entry,
        position=2,
        redaction_count=second_count,
    )

    log = replace(valid_log, entries=(first, second))

    with pytest.raises(ValueError):
        repository.create(
            INCIDENT_ID,
            log,
            source_redaction_count=source_count,
        )

    assert session.mock_calls == []


def test_nonempty_mutable_entry_collection_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_log: SanitizedLog,
    valid_entry: SanitizedLogEntry,
) -> None:
    invalid_entries: Any = [valid_entry]

    log = replace(
        valid_log,
        entries=invalid_entries,
    )

    with pytest.raises(ValueError):
        repository.create(INCIDENT_ID, log)

    assert session.mock_calls == []


class AdversarialPersistenceTimezone(_tzinfo):
    def __init__(self, behavior: str) -> None:
        self.behavior = behavior

    def utcoffset(self, dt: datetime | None) -> timedelta | None:
        if self.behavior == "none":
            return None
        if self.behavior == "type":
            raise TypeError("SYNTHETIC_TIMESTAMP_CANARY")
        if self.behavior == "value":
            raise ValueError("SYNTHETIC_TIMESTAMP_CANARY")
        if self.behavior == "overflow":
            raise OverflowError("SYNTHETIC_TIMESTAMP_CANARY")
        if self.behavior == "invalid_type":
            return cast(timedelta, "SYNTHETIC_TIMESTAMP_CANARY")
        return _timedelta(hours=24)

    def dst(self, dt: datetime | None) -> timedelta | None:
        raise NotImplementedError

    def tzname(self, dt: datetime | None) -> str | None:
        raise NotImplementedError


@pytest.mark.parametrize(
    "behavior", ("none", "type", "value", "overflow", "invalid_type", "invalid_range")
)
def test_adversarial_write_timezone_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_entry: SanitizedLogEntry,
    valid_log: SanitizedLog,
    behavior: str,
) -> None:
    timestamp = datetime(
        2026, 11, 24, 12, tzinfo=AdversarialPersistenceTimezone(behavior)
    )
    log = _replace(
        valid_log, entries=(_replace(valid_entry, event_timestamp=timestamp),)
    )
    with pytest.raises(ValueError) as captured:
        repository.create(INCIDENT_ID, log)
    assert "SYNTHETIC_TIMESTAMP_CANARY" not in str(captured.value)
    assert session.mock_calls == []


@pytest.mark.parametrize(
    "timestamp",
    (
        datetime.min.replace(tzinfo=_timezone(_timedelta(hours=1))),
        datetime.max.replace(tzinfo=_timezone(_timedelta(hours=-1))),
    ),
)
def test_adversarial_write_utc_overflow_rejected(
    repository: ApplicationLogRepository,
    session: MagicMock,
    valid_entry: SanitizedLogEntry,
    valid_log: SanitizedLog,
    timestamp: datetime,
) -> None:
    log = _replace(
        valid_log, entries=(_replace(valid_entry, event_timestamp=timestamp),)
    )
    with pytest.raises(ValueError):
        repository.create(INCIDENT_ID, log)
    assert session.mock_calls == []
