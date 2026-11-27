from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

import pytest

from app.core.config import Settings
from app.logs.contracts import (
    NormalizedLog,
    NormalizedLogEntry,
)
from app.logs.normalizer import LogNormalizer
from app.logs.sanitized_contracts import (
    SanitizedLog,
    SanitizedLogEntry,
)
from app.logs.sanitizer import (
    REDACTED_FIELD,
    LogSanitizer,
)
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.exceptions import (
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
)
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_SECRET_CANARY"


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 4096,
            "log_max_entries": 5,
            "log_max_message_chars": 1000,
            "log_max_metadata_chars": 200,
        }
    )


@pytest.fixture
def sanitizer(settings: Settings) -> LogSanitizer:
    return LogSanitizer(settings)


@pytest.fixture
def normalized_entry() -> NormalizedLogEntry:
    return NormalizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message="Synthetic application failure.",
        event_timestamp=datetime(2026, 11, 24, 15, 30, tzinfo=UTC),
        original_severity="ERROR",
        service_name="ticketing",
        exception="Connection timeout",
        error_code="TK-ERR",
        correlation_id="TXN-123",
    )


def make_log(
    *entries: NormalizedLogEntry,
    source_format: LogFormat = LogFormat.JSON,
    payload_bytes: int = 100,
) -> NormalizedLog:
    return NormalizedLog(
        source_format=source_format,
        payload_bytes=payload_bytes,
        entries=entries,
    )


def replace_text_field(
    entry: NormalizedLogEntry,
    name: str,
    value: str,
) -> NormalizedLogEntry:
    if name == "message":
        return replace(entry, message=value)

    if name == "original_severity":
        return replace(entry, original_severity=value)

    if name == "service_name":
        return replace(entry, service_name=value)

    if name == "exception":
        return replace(entry, exception=value)

    if name == "error_code":
        return replace(entry, error_code=value)

    if name == "correlation_id":
        return replace(entry, correlation_id=value)

    raise ValueError("Unsupported test field.")


def test_clean_log_preserved(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    result = sanitizer.sanitize(make_log(normalized_entry))

    entry = result.entries[0]

    assert isinstance(result, SanitizedLog)
    assert isinstance(entry, SanitizedLogEntry)

    assert result.source_format == LogFormat.JSON
    assert result.payload_bytes == 100
    assert result.entry_count == 1
    assert result.redaction_count == 0
    assert result.was_modified is False

    assert entry.position == normalized_entry.position
    assert entry.severity == normalized_entry.severity
    assert entry.message == normalized_entry.message
    assert entry.event_timestamp == (normalized_entry.event_timestamp)
    assert entry.original_severity == (normalized_entry.original_severity)
    assert entry.service_name == normalized_entry.service_name
    assert entry.exception == normalized_entry.exception
    assert entry.error_code == normalized_entry.error_code
    assert entry.correlation_id == normalized_entry.correlation_id
    assert entry.redaction_count == 0


def test_missing_optional_fields(
    sanitizer: LogSanitizer,
) -> None:
    source = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.UNKNOWN,
        message="Synthetic event",
    )

    entry = sanitizer.sanitize(make_log(source)).entries[0]

    assert entry.event_timestamp is None
    assert entry.original_severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None
    assert entry.redaction_count == 0


@pytest.mark.parametrize(
    "field",
    [
        "message",
        "original_severity",
        "service_name",
        "exception",
        "error_code",
        "correlation_id",
    ],
)
def test_every_text_field_is_sanitized(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
    field: str,
) -> None:
    value = f"password={CANARY}"

    source = replace_text_field(
        normalized_entry,
        field,
        value,
    )

    result = sanitizer.sanitize(make_log(source))

    entry = result.entries[0]
    sanitized_value = getattr(entry, field)

    assert isinstance(sanitized_value, str)
    assert CANARY not in sanitized_value
    assert sanitized_value == sanitize_text(value).text
    assert entry.redaction_count > 0
    assert result.redaction_count == entry.redaction_count
    assert result.was_modified is True


def test_all_fields_sanitized_together(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    value = f"password={CANARY}"

    source = replace(
        normalized_entry,
        message=value,
        original_severity=value,
        service_name=value,
        exception=value,
        error_code=value,
        correlation_id=value,
    )

    expected = sanitize_text(value)

    result = sanitizer.sanitize(make_log(source))

    entry = result.entries[0]

    fields = (
        entry.message,
        entry.original_severity,
        entry.service_name,
        entry.exception,
        entry.error_code,
        entry.correlation_id,
    )

    assert all(field == expected.text for field in fields)

    assert all(CANARY not in (field or "") for field in fields)

    assert expected.redaction_count > 0
    assert entry.redaction_count == (expected.redaction_count * 6)

    assert entry.severity == LogSeverity.ERROR
    assert entry.event_timestamp == source.event_timestamp


@pytest.mark.parametrize(
    "message",
    [
        f"password={CANARY}",
        f'password="{CANARY}"',
        f"password='{CANARY}'",
        f"Authorization: Bearer {CANARY}",
        f"Authorization: Basic {CANARY}",
        f"https://synthetic:{CANARY}@example.invalid/",
        (f"-----BEGIN PRIVATE KEY-----\n{CANARY}\n-----END PRIVATE KEY-----"),
    ],
)
def test_recognized_sensitive_patterns(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
    message: str,
) -> None:
    source = replace(
        normalized_entry,
        message=message,
    )

    result = sanitizer.sanitize(make_log(source))

    assert CANARY not in result.entries[0].message
    assert result.redaction_count > 0
    assert result.was_modified is True


def test_email_address_redacted(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    email = "synthetic.user@example.com"

    source = replace(
        normalized_entry,
        message=f"Authentication failed for {email}",
    )

    result = sanitizer.sanitize(make_log(source))

    assert email not in result.entries[0].message
    assert result.redaction_count > 0


def test_multiline_message_redacted(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    source = replace(
        normalized_entry,
        message=(f"Application failure\npassword={CANARY}\nRetry unavailable"),
    )

    entry = sanitizer.sanitize(make_log(source)).entries[0]

    assert CANARY not in entry.message
    assert "Application failure" in entry.message
    assert "Retry unavailable" in entry.message
    assert entry.redaction_count > 0


def test_redaction_count_aggregated(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    first = replace(
        normalized_entry,
        position=1,
        message=f"password={CANARY}",
    )

    second = replace(
        normalized_entry,
        position=2,
        message="Synthetic event without credentials",
    )

    third = replace(
        normalized_entry,
        position=3,
        message=f"password={CANARY}",
        exception=f"password={CANARY}",
    )

    result = sanitizer.sanitize(make_log(first, second, third))

    assert result.entry_count == 3
    assert result.entries[0].redaction_count > 0
    assert result.entries[1].redaction_count == 0
    assert result.entries[2].redaction_count > 0

    assert result.redaction_count == sum(
        entry.redaction_count for entry in result.entries
    )


def test_original_event_order_preserved(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    entries = tuple(
        replace(
            normalized_entry,
            position=position,
            message=f"Synthetic event {position}",
        )
        for position in range(1, 4)
    )

    result = sanitizer.sanitize(make_log(*entries))

    assert [entry.position for entry in result.entries] == [1, 2, 3]

    assert [entry.message for entry in result.entries] == [
        "Synthetic event 1",
        "Synthetic event 2",
        "Synthetic event 3",
    ]


@pytest.mark.parametrize(
    "source_format",
    list(LogFormat),
)
def test_source_format_preserved(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
    source_format: LogFormat,
) -> None:
    result = sanitizer.sanitize(
        make_log(
            normalized_entry,
            source_format=source_format,
        )
    )

    assert result.source_format == source_format


def test_original_payload_size_preserved(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    source = replace(
        normalized_entry,
        message=f"password={CANARY}",
    )

    result = sanitizer.sanitize(make_log(source, payload_bytes=2048))

    assert result.payload_bytes == 2048


def test_normalized_source_not_modified(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    source = replace(
        normalized_entry,
        message=f"password={CANARY}",
    )

    original = make_log(source)

    result = sanitizer.sanitize(original)

    assert CANARY in original.entries[0].message
    assert CANARY not in result.entries[0].message


def test_sanitization_is_deterministic(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    source = replace(
        normalized_entry,
        message=f"password={CANARY}",
    )

    original = make_log(source)

    assert sanitizer.sanitize(original) == sanitizer.sanitize(original)


def test_sanitized_entry_is_immutable(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    entry = sanitizer.sanitize(make_log(normalized_entry)).entries[0]

    with pytest.raises(FrozenInstanceError):
        type(entry).__setattr__(entry, "message", "Modified")


def test_sanitized_log_is_immutable(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    result = sanitizer.sanitize(make_log(normalized_entry))

    with pytest.raises(FrozenInstanceError):
        type(result).__setattr__(result, "payload_bytes", 200)


def test_text_fields_excluded_from_repr() -> None:
    entry = SanitizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message=CANARY,
        original_severity=CANARY,
        service_name=CANARY,
        exception=CANARY,
        error_code=CANARY,
        correlation_id=CANARY,
    )

    result = SanitizedLog(
        source_format=LogFormat.JSON,
        payload_bytes=100,
        entries=(entry,),
    )

    assert CANARY not in repr(entry)
    assert CANARY not in repr(result)


@pytest.mark.parametrize(
    "payload_bytes",
    [0, -1, -100],
)
def test_invalid_payload_size(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
    payload_bytes: int,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        sanitizer.sanitize(
            make_log(
                normalized_entry,
                payload_bytes=payload_bytes,
            )
        )


def test_oversized_payload(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    with pytest.raises(LogPayloadTooLargeError):
        sanitizer.sanitize(
            make_log(
                normalized_entry,
                payload_bytes=4097,
            )
        )


def test_empty_collection(
    sanitizer: LogSanitizer,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        sanitizer.sanitize(make_log())


def test_excessive_entry_count(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    entries = tuple(
        replace(
            normalized_entry,
            position=position,
        )
        for position in range(1, 7)
    )

    with pytest.raises(LogResourceLimitError):
        sanitizer.sanitize(make_log(*entries))


@pytest.mark.parametrize(
    "position",
    [0, -1, 2, 100],
)
def test_invalid_position(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
    position: int,
) -> None:
    source = replace(
        normalized_entry,
        position=position,
    )

    with pytest.raises(
        MalformedLogError,
        match="sequential",
    ):
        sanitizer.sanitize(make_log(source))


@pytest.mark.parametrize(
    "message",
    ["", " ", "\t\r\n"],
)
def test_empty_message_rejected(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
    message: str,
) -> None:
    source = replace(
        normalized_entry,
        message=message,
    )

    with pytest.raises(MalformedLogError):
        sanitizer.sanitize(make_log(source))


def test_oversized_sanitized_message_replaced(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    source = replace(
        normalized_entry,
        message="x" * 1001,
    )

    entry = sanitizer.sanitize(make_log(source)).entries[0]

    assert entry.message == REDACTED_FIELD
    assert entry.redaction_count == 1


def test_oversized_sanitized_metadata_replaced(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    source = replace(
        normalized_entry,
        service_name="x" * 201,
    )

    entry = sanitizer.sanitize(make_log(source)).entries[0]

    assert entry.service_name == REDACTED_FIELD
    assert entry.redaction_count == 1


def test_redaction_expansion_respects_limit(
    settings: Settings,
    normalized_entry: NormalizedLogEntry,
) -> None:
    limited = settings.model_copy(update={"log_max_metadata_chars": 32})

    value = "x" * 20 + " password=a"

    original_result = sanitize_text(value)

    assert len(value) <= 32
    assert original_result.redaction_count > 0

    source = replace(
        normalized_entry,
        service_name=value,
    )

    entry = LogSanitizer(limited).sanitize(make_log(source)).entries[0]

    assert entry.service_name is not None
    assert len(entry.service_name) <= 32
    assert "password=a" not in entry.service_name

    if len(original_result.text) > 32:
        assert entry.service_name == REDACTED_FIELD
        assert entry.redaction_count == (original_result.redaction_count + 1)
    else:
        assert entry.service_name == original_result.text


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<entry severity="ERROR">'
            b"<message>password=SYNTHETIC_SECRET_CANARY</message>"
            b"</entry>",
        ),
        (
            LogFormat.JSON,
            b'{"severity":"ERROR","message":"password=SYNTHETIC_SECRET_CANARY"}',
        ),
        (
            LogFormat.TEXT,
            b"ERROR password=SYNTHETIC_SECRET_CANARY",
        ),
    ],
)
def test_end_to_end_format_sanitization(
    settings: Settings,
    sanitizer: LogSanitizer,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    assert CANARY in normalized.entries[0].message

    result = sanitizer.sanitize(normalized)

    assert CANARY not in result.entries[0].message
    assert result.entries[0].severity == LogSeverity.ERROR
    assert result.source_format == source_format
    assert result.payload_bytes == len(payload)
    assert result.redaction_count > 0
    assert result.was_modified is True


def test_unicode_message_preserved(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    message = "Diagnostic caf\u00e9 \U0001f680"

    source = replace(
        normalized_entry,
        message=message,
    )

    entry = sanitizer.sanitize(make_log(source)).entries[0]

    assert entry.message == message
    assert entry.redaction_count == 0


def test_sanitizer_reusable_after_rejection(
    sanitizer: LogSanitizer,
    normalized_entry: NormalizedLogEntry,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        sanitizer.sanitize(make_log())

    result = sanitizer.sanitize(make_log(normalized_entry))

    assert result.entry_count == 1
    assert result.was_modified is False
