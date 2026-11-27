import json

import pytest

from app.core.config import Settings
from app.models.log_enums import LogFormat
from app.parsers.contracts import LogParser
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    InvalidLogPayloadError,
    LogPayloadTooLargeError,
    LogResourceLimitError,
    MalformedLogError,
)
from app.parsers.json_parser import JSONLogParser


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 1024,
            "log_max_entries": 3,
            "log_max_nesting_depth": 5,
            "log_max_message_chars": 100,
            "log_max_metadata_chars": 32,
        }
    )


def test_parser_protocol() -> None:
    assert isinstance(JSONLogParser(), LogParser)


def test_complete_json_entry(settings: Settings) -> None:
    payload = json.dumps(
        {
            "timestamp": "2026-11-24T15:30:00Z",
            "severity": "ERROR",
            "service_name": "ticketing",
            "message": "Ticketing failed.",
            "exception": "Connection timeout",
            "error_code": "TK-ERR",
            "correlation_id": "TXN-10482",
        }
    ).encode()

    result = JSONLogParser().parse(payload, settings)

    assert result.source_format == LogFormat.JSON
    assert result.payload_bytes == len(payload)
    assert len(result.entries) == 1

    entry = result.entries[0]

    assert entry.position == 1
    assert entry.message == "Ticketing failed."
    assert entry.timestamp == "2026-11-24T15:30:00Z"
    assert entry.severity == "ERROR"
    assert entry.service_name == "ticketing"
    assert entry.exception == "Connection timeout"
    assert entry.error_code == "TK-ERR"
    assert entry.correlation_id == "TXN-10482"


def test_single_entry(settings: Settings) -> None:
    result = JSONLogParser().parse(
        b'{"message":"Ready"}',
        settings,
    )

    assert len(result.entries) == 1
    assert result.entries[0].message == "Ready"


def test_array_of_entries(settings: Settings) -> None:
    payload = b"""
    [
        {"message":"First"},
        {"message":"Second"},
        {"message":"Third"}
    ]
    """

    result = JSONLogParser().parse(payload, settings)

    assert [entry.position for entry in result.entries] == [1, 2, 3]

    assert [entry.message for entry in result.entries] == ["First", "Second", "Third"]


@pytest.mark.parametrize(
    "wrapper",
    ["entries", "logs", "events"],
)
def test_wrapped_collection(
    settings: Settings,
    wrapper: str,
) -> None:
    payload = json.dumps(
        {
            wrapper: [
                {"message": "First"},
                {"message": "Second"},
            ]
        }
    ).encode()

    result = JSONLogParser().parse(payload, settings)

    assert len(result.entries) == 2
    assert result.entries[0].message == "First"
    assert result.entries[1].message == "Second"


def test_missing_optional_metadata(
    settings: Settings,
) -> None:
    entry = (
        JSONLogParser()
        .parse(
            b'{"message":"Ready"}',
            settings,
        )
        .entries[0]
    )

    assert entry.timestamp is None
    assert entry.severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_null_optional_metadata(
    settings: Settings,
) -> None:
    payload = b"""
    {
        "message": "Ready",
        "timestamp": null,
        "severity": null,
        "service_name": null,
        "exception": null,
        "error_code": null,
        "correlation_id": null
    }
    """

    entry = (
        JSONLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.timestamp is None
    assert entry.severity is None
    assert entry.service_name is None
    assert entry.exception is None
    assert entry.error_code is None
    assert entry.correlation_id is None


def test_whitespace_normalization(
    settings: Settings,
) -> None:
    payload = b'{"message":"  Ready  ","severity":" INFO ","service_name":"   "}'

    entry = (
        JSONLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == "Ready"
    assert entry.severity == "INFO"
    assert entry.service_name is None


@pytest.mark.parametrize(
    "message",
    [
        "Diagnostic caf\u00e9",
        "Unicode \u65e5\u672c",
        "Unicode \U0001f680",
        "Line one\nLine two",
        "Column one\tColumn two",
        'Received "quoted" text',
        "Path C:\\synthetic\\logs",
        "Literal brackets {{{[[[",
        "Literal closing brackets }}}]]]",
    ],
)
def test_valid_message_content(
    settings: Settings,
    message: str,
) -> None:
    payload = json.dumps({"message": message}).encode()

    result = JSONLogParser().parse(
        payload,
        settings,
    )

    assert result.entries[0].message == message


def test_utf8_bom(settings: Settings) -> None:
    payload = b'\xef\xbb\xbf{"message":"Ready"}'

    result = JSONLogParser().parse(payload, settings)

    assert result.entries[0].message == "Ready"
    assert result.payload_bytes == len(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b" ",
        b"\t\r\n",
        b"\xef\xbb\xbf",
    ],
)
def test_empty_payload(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        JSONLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"entries":[]}',
        b'{"logs":[]}',
        b'{"events":[]}',
    ],
)
def test_empty_collections(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogPayloadError):
        JSONLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"message":',
        b'{"message":"Ready"',
        b'{"message":"Ready",}',
        b'[{"message":"Ready"},]',
        b'{"message":"Ready"]',
        b"}",
        b'{"message":"Ready"}{}',
        b'{"message":"unterminated}',
        b"{message: 'Ready'}",
        b"Not JSON",
    ],
)
def test_malformed_json(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        JSONLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b"null",
        b"true",
        b'"Ready"',
        b"123",
        b"1.5",
        b"[null]",
        b"[true]",
        b'["Ready"]',
        b"[[]]",
        b'{"entries":{}}',
        b'{"entries":null}',
        b'{"entries":"Ready"}',
        b'{"entries":[],"source":"application"}',
        b'{"entries":[],"logs":[]}',
    ],
)
def test_unsupported_document_structure(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        JSONLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"severity":"ERROR"}',
        b'{"message":null}',
        b'{"message":""}',
        b'{"message":"   "}',
        b'{"message":true}',
        b'{"message":123}',
        b'{"message":1.5}',
        b'{"message":[]}',
        b'{"message":{}}',
        b'{"message":"Ready","severity":false}',
        b'{"message":"Ready","exception":{}}',
        b'{"message":"Ready","unsupported":"value"}',
    ],
)
def test_invalid_log_fields(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError):
        JSONLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"message":"First","message":"Second"}',
        b'{"message":"Ready","severity":"INFO","severity":"ERROR"}',
        b'{"entries":[],"entries":[]}',
        b'{"message":"First","\\u006dessage":"Second"}',
    ],
)
def test_duplicate_keys_rejected(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(
        MalformedLogError,
        match="duplicate key",
    ):
        JSONLogParser().parse(payload, settings)


@pytest.mark.parametrize(
    "constant",
    ["NaN", "Infinity", "-Infinity"],
)
def test_nonstandard_numeric_constants(
    settings: Settings,
    constant: str,
) -> None:
    payload = ('{"message":' + constant + "}").encode()

    with pytest.raises(MalformedLogError):
        JSONLogParser().parse(payload, settings)


def test_excessive_nesting(settings: Settings) -> None:
    payload = b"[" * 20 + b'{"message":"Ready"}' + b"]" * 20

    with pytest.raises(LogResourceLimitError):
        JSONLogParser().parse(payload, settings)


def test_exact_nesting_limit(
    settings: Settings,
) -> None:
    limited = settings.model_copy(update={"log_max_nesting_depth": 3})

    payload = b'{"entries":[{"message":"Ready"}]}'

    result = JSONLogParser().parse(
        payload,
        limited,
    )

    assert result.entries[0].message == "Ready"


def test_nesting_limit_exceeded_by_one(
    settings: Settings,
) -> None:
    limited = settings.model_copy(update={"log_max_nesting_depth": 2})

    payload = b'{"entries":[{"message":"Ready"}]}'

    with pytest.raises(LogResourceLimitError):
        JSONLogParser().parse(payload, limited)


def test_entry_count_limit(settings: Settings) -> None:
    payload = json.dumps([{"message": "Ready"}] * 4).encode()

    with pytest.raises(LogResourceLimitError):
        JSONLogParser().parse(payload, settings)


def test_exact_entry_count_limit(
    settings: Settings,
) -> None:
    payload = json.dumps([{"message": "Ready"}] * 3).encode()

    result = JSONLogParser().parse(payload, settings)

    assert len(result.entries) == 3


def test_payload_size_limit(
    settings: Settings,
) -> None:
    with pytest.raises(LogPayloadTooLargeError):
        JSONLogParser().parse(
            b"x" * 1025,
            settings,
        )


@pytest.mark.parametrize(
    "field",
    ["message", "exception"],
)
def test_message_field_limits(
    settings: Settings,
    field: str,
) -> None:
    document = {"message": "Ready"}
    document[field] = "x" * 101

    payload = json.dumps(document).encode()

    with pytest.raises(LogResourceLimitError):
        JSONLogParser().parse(payload, settings)


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
def test_metadata_field_limits(
    settings: Settings,
    field: str,
) -> None:
    payload = json.dumps(
        {
            "message": "Ready",
            field: "x" * 33,
        }
    ).encode()

    with pytest.raises(LogResourceLimitError):
        JSONLogParser().parse(payload, settings)


def test_exact_field_limits(
    settings: Settings,
) -> None:
    message = "m" * 100
    service_name = "s" * 32

    payload = json.dumps(
        {
            "message": message,
            "service_name": service_name,
        }
    ).encode()

    entry = (
        JSONLogParser()
        .parse(
            payload,
            settings,
        )
        .entries[0]
    )

    assert entry.message == message
    assert entry.service_name == service_name


@pytest.mark.parametrize(
    "payload",
    [
        b'{"message":"Ready\\u0000"}',
        b'{"message":"Ready\\u0001"}',
        b'{"message":"Ready\\u001b"}',
        b'{"message":"Ready\\u007f"}',
        b'{"message":"Ready\\u0085"}',
        b'{"message":"Ready\\ud800"}',
        b'{"message":"Ready\\udfff"}',
        b'{"message":"Ready","severity":"INFO\\u0000"}',
        b'{"message":"Ready\\b"}',
        b'{"message":"Ready\\f"}',
    ],
)
def test_unsupported_encoded_characters(
    settings: Settings,
    payload: bytes,
) -> None:
    with pytest.raises(InvalidLogEncodingError):
        JSONLogParser().parse(payload, settings)


def test_invalid_utf8(settings: Settings) -> None:
    payload = b'{"message":"\xff"}'

    with pytest.raises(InvalidLogEncodingError):
        JSONLogParser().parse(payload, settings)


def test_error_does_not_expose_payload(
    settings: Settings,
) -> None:
    payload = b'{"message":"SYNTHETIC_SECRET_CANARY"'

    with pytest.raises(MalformedLogError) as captured:
        JSONLogParser().parse(payload, settings)

    assert "SYNTHETIC_SECRET_CANARY" not in str(captured.value)

    assert captured.value.__suppress_context__ is True


def test_unknown_field_does_not_expose_value(
    settings: Settings,
) -> None:
    payload = b'{"message":"Ready","unsupported":"SYNTHETIC_SECRET_CANARY"}'

    with pytest.raises(MalformedLogError) as captured:
        JSONLogParser().parse(payload, settings)

    assert "SYNTHETIC_SECRET_CANARY" not in str(captured.value)


def test_parser_reusable_after_rejection(
    settings: Settings,
) -> None:
    parser = JSONLogParser()

    with pytest.raises(MalformedLogError):
        parser.parse(
            b'{"message":"First","message":"Second"}',
            settings,
        )

    result = parser.parse(
        b'{"message":"Ready"}',
        settings,
    )

    assert result.entries[0].message == "Ready"
    assert result.entries[0].position == 1
