from dataclasses import FrozenInstanceError

import pytest

from app.core.config import Settings
from app.core.exceptions import ApplicationError
from app.models.log_enums import LogFormat
from app.parsers.contracts import (
    LogParser,
    ParsedLog,
    ParsedLogEntry,
)
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogParsingError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
    UnsafeLogContentError,
)
from app.parsers.validation import (
    decode_log_payload,
    validate_entry_count,
    validate_nesting_depth,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 1024,
            "log_max_entries": 3,
            "log_max_nesting_depth": 4,
        }
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"Application error", "Application error"),
        (b"\xef\xbb\xbfApplication error", "Application error"),
        (b"INFO\tReady\r\n", "INFO\tReady\r\n"),
        ("Diagnostic caf\u00e9".encode(), "Diagnostic caf\u00e9"),
        (b"  Application error  ", "  Application error  "),
    ],
)
def test_valid_payload_decoding(
    settings: Settings,
    payload: bytes,
    expected: str,
) -> None:
    assert decode_log_payload(payload, settings) == expected


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b" ",
        b"\t\r\n",
        b"\xef\xbb\xbf",
    ],
)
def test_empty_payload_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        decode_log_payload(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff\xfeinvalid",
        b"\x80invalid",
        b"\xc3",
        b"\xed\xa0\x80",
    ],
)
def test_invalid_utf8_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogEncodingError) as captured:
        decode_log_payload(payload, settings)

    assert captured.value.__suppress_context__ is True


@pytest.mark.parametrize(
    "payload",
    [
        b"error\x00message",
        b"error\x01message",
        b"error\x1bmessage",
        b"error\x7fmessage",
        "error\u0085message".encode(),
    ],
)
def test_control_characters_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogEncodingError):
        decode_log_payload(payload, settings)


def test_exact_payload_limit(
    settings: Settings,
) -> None:
    payload = b"a" * 1024

    assert len(decode_log_payload(payload, settings)) == 1024


def test_oversized_payload(
    settings: Settings,
) -> None:
    with pytest.raises(LogPayloadTooLargeError):
        decode_log_payload(b"a" * 1025, settings)


def test_byte_limit_not_character_limit(
    settings: Settings,
) -> None:
    payload = ("\u00e9" * 513).encode()

    with pytest.raises(LogPayloadTooLargeError):
        decode_log_payload(payload, settings)


def test_size_checked_before_decoding(
    settings: Settings,
) -> None:
    with pytest.raises(LogPayloadTooLargeError):
        decode_log_payload(b"\xff" * 1025, settings)


@pytest.mark.parametrize("count", [1, 2, 3])
def test_valid_entry_count(
    settings: Settings,
    count: int,
) -> None:
    validate_entry_count(count, settings)


@pytest.mark.parametrize("count", [-1, 0])
def test_empty_entry_count_rejected(
    settings: Settings,
    count: int,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        validate_entry_count(count, settings)


def test_excessive_entry_count(
    settings: Settings,
) -> None:
    with pytest.raises(LogResourceLimitError):
        validate_entry_count(4, settings)


@pytest.mark.parametrize("depth", [0, 1, 4])
def test_valid_nesting_depth(
    settings: Settings,
    depth: int,
) -> None:
    validate_nesting_depth(depth, settings)


@pytest.mark.parametrize("depth", [-1, 5])
def test_invalid_nesting_depth(
    settings: Settings,
    depth: int,
) -> None:
    with pytest.raises(LogResourceLimitError):
        validate_nesting_depth(depth, settings)


@pytest.mark.parametrize(
    "exception_type",
    [
        InvalidLogPayloadError,
        LogPayloadTooLargeError,
        InvalidLogEncodingError,
        MalformedLogError,
        UnsafeLogContentError,
        LogResourceLimitError,
    ],
)
def test_parser_exception_hierarchy(
    exception_type: type[LogParsingError],
) -> None:
    error = exception_type("Safe diagnostic message.")

    assert isinstance(error, LogParsingError)
    assert isinstance(error, ApplicationError)
    assert str(error) == "Safe diagnostic message."


def test_parsed_entry_defaults() -> None:
    entry = ParsedLogEntry(
        position=1,
        message="Application failure.",
    )

    assert entry.position == 1
    assert entry.message == "Application failure."
    assert entry.timestamp is None
    assert entry.severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_parsed_log_contract() -> None:
    entry = ParsedLogEntry(
        position=1,
        message="Synthetic event.",
    )

    result = ParsedLog(
        source_format=LogFormat.XML,
        payload_bytes=100,
        entries=(entry,),
    )

    assert result.source_format == LogFormat.XML
    assert result.payload_bytes == 100
    assert result.entries == (entry,)


def test_parsed_entry_is_immutable() -> None:
    entry = ParsedLogEntry(
        position=1,
        message="Synthetic event.",
    )

    with pytest.raises(FrozenInstanceError):
        type(entry).__setattr__(entry, "message", "Modified")


def test_parsed_log_is_immutable() -> None:
    result = ParsedLog(
        source_format=LogFormat.JSON,
        payload_bytes=100,
        entries=(),
    )

    with pytest.raises(FrozenInstanceError):
        type(result).__setattr__(result, "payload_bytes", 200)


def test_log_parser_protocol(
    settings: Settings,
) -> None:
    class SyntheticParser:
        def parse(
            self,
            payload: bytes,
            settings: Settings,
        ) -> ParsedLog:
            content = decode_log_payload(
                payload,
                settings,
            )

            return ParsedLog(
                source_format=LogFormat.TEXT,
                payload_bytes=len(payload),
                entries=(
                    ParsedLogEntry(
                        position=1,
                        message=content,
                    ),
                ),
            )

    parser: LogParser = SyntheticParser()

    assert isinstance(parser, LogParser)

    result = parser.parse(
        b"Synthetic event",
        settings,
    )

    assert result.entries[0].message == "Synthetic event"


def test_unrelated_object_is_not_parser() -> None:
    assert not isinstance(object(), LogParser)


def test_validation_error_does_not_expose_payload(
    settings: Settings,
) -> None:
    payload = b"\xffSYNTHETIC_SECRET_CANARY"

    with pytest.raises(InvalidLogEncodingError) as captured:
        decode_log_payload(payload, settings)

    assert "SYNTHETIC_SECRET_CANARY" not in str(captured.value)
