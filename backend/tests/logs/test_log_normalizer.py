from dataclasses import replace
from datetime import UTC, datetime

import pytest

from app.core.config import Settings
from app.logs.normalizer import LogNormalizer
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.contracts import ParsedLog, ParsedLogEntry
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 4096,
            "log_max_entries": 5,
            "log_max_message_chars": 100,
            "log_max_metadata_chars": 32,
        }
    )


@pytest.fixture
def normalizer(
    settings: Settings,
) -> LogNormalizer:
    return LogNormalizer(settings)


@pytest.fixture
def parsed_entry() -> ParsedLogEntry:
    return ParsedLogEntry(
        position=1,
        message="Synthetic application failure.",
        timestamp="2026-11-24T10:30:00-05:00",
        severity="FATAL",
        service_name="ticketing",
        exception="Connection timeout",
        error_code="TK-ERR",
        correlation_id="TXN-123",
    )


def make_parsed_log(
    *entries: ParsedLogEntry,
    source_format: LogFormat = LogFormat.JSON,
    payload_bytes: int = 100,
) -> ParsedLog:
    return ParsedLog(
        source_format=source_format,
        payload_bytes=payload_bytes,
        entries=entries,
    )


def replace_text_field(
    entry: ParsedLogEntry,
    field: str,
    value: str,
) -> ParsedLogEntry:
    if field == "message":
        return replace(entry, message=value)

    if field == "timestamp":
        return replace(entry, timestamp=value)

    if field == "severity":
        return replace(entry, severity=value)

    if field == "service_name":
        return replace(entry, service_name=value)

    if field == "exception":
        return replace(entry, exception=value)

    if field == "error_code":
        return replace(entry, error_code=value)

    if field == "correlation_id":
        return replace(entry, correlation_id=value)

    raise ValueError("Unsupported test field.")


def test_complete_entry_normalization(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    result = normalizer.normalize(make_parsed_log(parsed_entry))

    assert result.source_format == LogFormat.JSON
    assert result.payload_bytes == 100
    assert result.entry_count == 1

    entry = result.entries[0]

    assert entry.position == 1
    assert entry.severity == LogSeverity.CRITICAL
    assert entry.original_severity == "FATAL"

    assert entry.event_timestamp == datetime(2026, 11, 24, 15, 30, tzinfo=UTC)

    assert entry.message == ("Synthetic application failure.")

    assert entry.service_name == "ticketing"
    assert entry.exception == "Connection timeout"
    assert entry.error_code == "TK-ERR"
    assert entry.correlation_id == "TXN-123"


def test_missing_optional_fields(
    normalizer: LogNormalizer,
) -> None:
    parsed = make_parsed_log(
        ParsedLogEntry(
            position=1,
            message="Synthetic event",
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.severity == LogSeverity.UNKNOWN
    assert entry.event_timestamp is None
    assert entry.original_severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_empty_optional_fields(
    normalizer: LogNormalizer,
) -> None:
    parsed = make_parsed_log(
        ParsedLogEntry(
            position=1,
            message="Ready",
            timestamp=" ",
            severity="",
            service_name="\t",
            exception="\r\n",
            error_code=" ",
            correlation_id="",
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.severity == LogSeverity.UNKNOWN
    assert entry.event_timestamp is None
    assert entry.original_severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_surrounding_whitespace_normalized(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message="  Synthetic event  ",
            severity="  WaRn  ",
            service_name="  ticketing  ",
            error_code="  TK-ERR  ",
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.message == "Synthetic event"
    assert entry.severity == LogSeverity.WARNING
    assert entry.original_severity == "WaRn"
    assert entry.service_name == "ticketing"
    assert entry.error_code == "TK-ERR"


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        ("TRACE", LogSeverity.TRACE),
        ("DEBUG", LogSeverity.DEBUG),
        ("NOTICE", LogSeverity.INFO),
        ("WARN", LogSeverity.WARNING),
        ("ERR", LogSeverity.ERROR),
        ("FATAL", LogSeverity.CRITICAL),
        ("CUSTOM", LogSeverity.UNKNOWN),
        (None, LogSeverity.UNKNOWN),
    ],
)
def test_severity_mapping(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    original: str | None,
    expected: LogSeverity,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            severity=original,
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.severity == expected
    assert entry.original_severity == original


@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        "",
        "Invalid timestamp",
        "2026-11-24T15:30:00",
        "2026-99-99T99:99:99Z",
        "2026-11-24T15:30:00-00:00",
    ],
)
def test_invalid_timestamp_does_not_reject_event(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    timestamp: str | None,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            timestamp=timestamp,
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.event_timestamp is None
    assert entry.message == parsed_entry.message


@pytest.mark.parametrize(
    "source_format",
    list(LogFormat),
)
def test_original_format_preserved(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    source_format: LogFormat,
) -> None:
    result = normalizer.normalize(
        make_parsed_log(
            parsed_entry,
            source_format=source_format,
        )
    )

    assert result.source_format == source_format


def test_event_order_preserved(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            position=1,
            message="First",
        ),
        replace(
            parsed_entry,
            position=2,
            message="Second",
        ),
        replace(
            parsed_entry,
            position=3,
            message="Third",
        ),
    )

    result = normalizer.normalize(parsed)

    assert result.entry_count == 3

    assert [entry.position for entry in result.entries] == [1, 2, 3]

    assert [entry.message for entry in result.entries] == ["First", "Second", "Third"]


@pytest.mark.parametrize(
    "positions",
    [
        [0],
        [-1],
        [2],
        [1, 1],
        [1, 3],
        [2, 1],
        [1, 2, 4],
    ],
)
def test_invalid_positions_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    positions: list[int],
) -> None:
    entries = tuple(
        replace(
            parsed_entry,
            position=position,
        )
        for position in positions
    )

    with pytest.raises(
        MalformedLogError,
        match="sequential",
    ):
        normalizer.normalize(make_parsed_log(*entries))


@pytest.mark.parametrize(
    "message",
    ["", " ", "\t\r\n"],
)
def test_empty_messages_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    message: str,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message=message,
        )
    )

    with pytest.raises(
        MalformedLogError,
        match="nonempty message",
    ):
        normalizer.normalize(parsed)


@pytest.mark.parametrize(
    "payload_bytes",
    [0, -1, -100],
)
def test_invalid_payload_sizes_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    payload_bytes: int,
) -> None:
    parsed = make_parsed_log(
        parsed_entry,
        payload_bytes=payload_bytes,
    )

    with pytest.raises(InvalidLogPayloadError):
        normalizer.normalize(parsed)


def test_oversized_payload_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(
        parsed_entry,
        payload_bytes=4097,
    )

    with pytest.raises(LogPayloadTooLargeError):
        normalizer.normalize(parsed)


def test_exact_payload_limit(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(
        parsed_entry,
        payload_bytes=4096,
    )

    assert normalizer.normalize(parsed).payload_bytes == 4096


def test_empty_collection_rejected(
    normalizer: LogNormalizer,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        normalizer.normalize(make_parsed_log())


@pytest.mark.parametrize("count", [1, 3, 5])
def test_valid_entry_counts(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    count: int,
) -> None:
    entries = tuple(
        replace(
            parsed_entry,
            position=position,
        )
        for position in range(1, count + 1)
    )

    result = normalizer.normalize(make_parsed_log(*entries))

    assert result.entry_count == count


def test_excessive_entry_count_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    entries = tuple(
        replace(
            parsed_entry,
            position=position,
        )
        for position in range(1, 7)
    )

    with pytest.raises(LogResourceLimitError):
        normalizer.normalize(make_parsed_log(*entries))


@pytest.mark.parametrize(
    "field",
    ["message", "exception"],
)
def test_oversized_message_fields(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    field: str,
) -> None:
    parsed = make_parsed_log(
        replace_text_field(
            parsed_entry,
            field,
            "x" * 101,
        ),
    )

    with pytest.raises(LogResourceLimitError):
        normalizer.normalize(parsed)


@pytest.mark.parametrize(
    "field",
    [
        "timestamp",
        "severity",
        "service_name",
        "error_code",
        "correlation_id",
    ],
)
def test_oversized_metadata_fields(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    field: str,
) -> None:
    parsed = make_parsed_log(
        replace_text_field(
            parsed_entry,
            field,
            "x" * 33,
        ),
    )

    with pytest.raises(LogResourceLimitError):
        normalizer.normalize(parsed)


def test_exact_field_limits(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message="m" * 100,
            exception="e" * 100,
            service_name="s" * 32,
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.message == "m" * 100
    assert entry.exception == "e" * 100
    assert entry.service_name == "s" * 32


@pytest.mark.parametrize(
    "character",
    [
        "\x00",
        "\x01",
        "\x1b",
        "\x7f",
        "\u0085",
        "\u009f",
        "\ud800",
        "\udfff",
    ],
)
def test_invalid_characters_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    character: str,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message=f"Synthetic{character}event",
        )
    )

    with pytest.raises(InvalidLogEncodingError):
        normalizer.normalize(parsed)


@pytest.mark.parametrize(
    "field",
    [
        "timestamp",
        "severity",
        "service_name",
        "exception",
        "error_code",
        "correlation_id",
    ],
)
def test_invalid_metadata_characters_rejected(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
    field: str,
) -> None:
    parsed = make_parsed_log(
        replace_text_field(
            parsed_entry,
            field,
            "Synthetic\x00value",
        ),
    )

    with pytest.raises(InvalidLogEncodingError):
        normalizer.normalize(parsed)


def test_multiline_message_preserved(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    message = "Application failure\nConnection timeout\n\tRetry unavailable"

    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message=message,
        )
    )

    assert normalizer.normalize(parsed).entries[0].message == message


def test_unicode_preserved(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    message = "Diagnostic caf\u00e9 \U0001f680"

    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message=message,
        )
    )

    assert normalizer.normalize(parsed).entries[0].message == message


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<entry severity="FATAL" '
            b'timestamp="2026-11-24T10:30:00-05:00" '
            b'service_name="ticketing" '
            b'message="Automation failed"/>',
        ),
        (
            LogFormat.JSON,
            b'{"severity":"FATAL",'
            b'"timestamp":"2026-11-24T10:30:00-05:00",'
            b'"service_name":"ticketing",'
            b'"message":"Automation failed"}',
        ),
        (
            LogFormat.TEXT,
            b"2026-11-24T10:30:00-05:00 FATAL [ticketing] Automation failed",
        ),
    ],
)
def test_end_to_end_format_normalization(
    normalizer: LogNormalizer,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    result = normalizer.parse_and_normalize(
        payload,
        source_format,
    )

    assert result.source_format == source_format
    assert result.payload_bytes == len(payload)
    assert result.entry_count == 1

    entry = result.entries[0]

    assert entry.position == 1
    assert entry.severity == LogSeverity.CRITICAL
    assert entry.original_severity == "FATAL"
    assert entry.service_name == "ticketing"
    assert entry.message == "Automation failed"

    assert entry.event_timestamp == datetime(2026, 11, 24, 15, 30, tzinfo=UTC)


def test_equivalent_formats_produce_equal_entries(
    normalizer: LogNormalizer,
) -> None:
    xml = normalizer.parse_and_normalize(
        b'<entry severity="ERROR" message="Failure"/>',
        LogFormat.XML,
    )

    structured = normalizer.parse_and_normalize(
        b'{"severity":"ERROR","message":"Failure"}',
        LogFormat.JSON,
    )

    plain = normalizer.parse_and_normalize(
        b"ERROR Failure",
        LogFormat.TEXT,
    )

    assert xml.entries == structured.entries
    assert structured.entries == plain.entries


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (LogFormat.XML, b"<entry>"),
        (LogFormat.JSON, b'{"message":'),
        (LogFormat.TEXT, b"ERROR"),
    ],
)
def test_parser_errors_propagate(
    normalizer: LogNormalizer,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        normalizer.parse_and_normalize(
            payload,
            source_format,
        )


def test_xml_security_error_propagates(
    normalizer: LogNormalizer,
) -> None:
    payload = b'<!DOCTYPE entry><entry message="Ready"/>'

    with pytest.raises(UnsafeLogContentError):
        normalizer.parse_and_normalize(
            payload,
            LogFormat.XML,
        )


def test_rejected_content_not_exposed(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(
        replace(
            parsed_entry,
            message="SYNTHETIC_SECRET_CANARY" + "x" * 100,
        )
    )

    with pytest.raises(LogResourceLimitError) as captured:
        normalizer.normalize(parsed)

    assert "SYNTHETIC_SECRET_CANARY" not in str(captured.value)


def test_normalization_does_not_modify_source(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    original = replace(
        parsed_entry,
        severity="  FATAL  ",
        message="  Failure  ",
    )

    parsed = make_parsed_log(original)

    result = normalizer.normalize(parsed)

    assert original.severity == "  FATAL  "
    assert original.message == "  Failure  "

    assert result.entries[0].original_severity == "FATAL"
    assert result.entries[0].message == "Failure"


def test_normalization_is_deterministic(
    normalizer: LogNormalizer,
    parsed_entry: ParsedLogEntry,
) -> None:
    parsed = make_parsed_log(parsed_entry)

    first = normalizer.normalize(parsed)
    second = normalizer.normalize(parsed)

    assert first == second


def test_message_severity_not_inferred(
    normalizer: LogNormalizer,
) -> None:
    parsed = make_parsed_log(
        ParsedLogEntry(
            position=1,
            message="Critical database failure",
        )
    )

    entry = normalizer.normalize(parsed).entries[0]

    assert entry.severity == LogSeverity.UNKNOWN


def test_normalizer_reusable_after_rejection(
    normalizer: LogNormalizer,
) -> None:
    with pytest.raises(MalformedLogError):
        normalizer.parse_and_normalize(
            b"<entry>",
            LogFormat.XML,
        )

    result = normalizer.parse_and_normalize(
        b'{"message":"Recovered"}',
        LogFormat.JSON,
    )

    assert result.entry_count == 1
    assert result.entries[0].message == "Recovered"
    assert result.entries[0].position == 1


def test_normalized_records_remain_unsanitized(
    normalizer: LogNormalizer,
) -> None:
    parsed = make_parsed_log(
        ParsedLogEntry(
            position=1,
            message="password=SYNTHETIC_SECRET_CANARY",
        )
    )

    result = normalizer.normalize(parsed)

    assert result.entries[0].message == ("password=SYNTHETIC_SECRET_CANARY")
