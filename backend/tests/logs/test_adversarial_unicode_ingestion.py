import json
from unittest.mock import MagicMock
from uuid import uuid4
from xml.sax.saxutils import escape

import pytest

from app.core.config import Settings
from app.logs.normalizer import LogNormalizer
from app.logs.outbound_security import validate_outbound_text
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    UnsafeLogContentError,
)
from app.services.log_ingestion import LogIngestionService

CANARY = "SYNTHETIC_UNICODE_INGESTION_CANARY"

ENCODINGS = (
    (LogFormat.TEXT, False),
    (LogFormat.JSON, False),
    (LogFormat.JSON, True),
    (LogFormat.XML, False),
    (LogFormat.XML, True),
)

LABELS = (
    "password",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret_key",
)

DELIMITERS = (
    ":",
    "\uff1d",
    "\ufe55",
    "\ufe66",
)

JOINERS = (
    "\u200c",
    "\u200d",
)

AUTHORIZATION_SCHEMES = (
    "Bearer",
    "Basic",
    "\uff22\uff45\uff41\uff52\uff45\uff52",
    "\uff22\uff41\uff53\uff49\uff43",
    "B\uff45arer",
    "B\uff41sic",
)

UNSUPPORTED_CONTROLS = (
    "\u00ad",
    "\u061c",
    "\u200b",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2060",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\ufeff",
)

INTERNATIONAL_TEXT = (
    "\u63a5\u7d9a\u306b\u5931\u6557",
    "\u670d\u52a1\u4e0d\u53ef\u7528",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0646\u0645\u06cc\u200c\u0634\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "\u0915\u094d\u200c\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\U0001f468\u200d\U0001f469\u200d\U0001f467",
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


def xml_text(value: str, escaped: bool) -> str:
    if not escaped:
        return escape(value)

    return "".join(
        f"&#x{ord(character):x};" if ord(character) > 127 else escape(character)
        for character in value
    )


def make_payload(
    source_format: LogFormat,
    escaped: bool,
    message: str,
) -> bytes:
    if source_format == LogFormat.JSON:
        return json.dumps(
            {
                "severity": "ERROR",
                "message": message,
            },
            ensure_ascii=escaped,
        ).encode("utf-8")

    if source_format == LogFormat.XML:
        return (
            '<entry severity="ERROR"><message>'
            + xml_text(message, escaped)
            + "</message></entry>"
        ).encode("utf-8")

    return f"ERROR {message}".encode()


ASSIGNMENT_PREFIXES = tuple(
    fullwidth(label) + delimiter for label in LABELS for delimiter in DELIMITERS
)

COMPOUND_PREFIXES = tuple(
    fullwidth(label.split("_")[0])
    + separator
    + fullwidth(label.split("_")[1])
    + delimiter
    for label in LABELS
    if "_" in label
    for separator in (
        "_\u00a0",
        "\uff3f\u3000",
        "-\u2003_",
    )
    for delimiter in DELIMITERS
)

REDACTION_CASES = tuple(
    (
        prefix + CANARY,
        prefix + "[REDACTED_SECRET]",
    )
    for prefix in (ASSIGNMENT_PREFIXES + COMPOUND_PREFIXES)
) + tuple(
    (
        scheme + separator + CANARY,
        scheme + " [REDACTED_TOKEN]",
    )
    for scheme in AUTHORIZATION_SCHEMES
    for separator in (" ", "\u00a0", "\u3000")
)

JOINER_CASES = tuple(
    prefix[0] + joiner + prefix[1:] + CANARY
    for prefix in ASSIGNMENT_PREFIXES
    for joiner in JOINERS
) + tuple(
    scheme[0] + joiner + scheme[1:] + "\u3000" + CANARY
    for scheme in AUTHORIZATION_SCHEMES
    for joiner in JOINERS
)

MALFORMED_MARKERS = tuple(
    scheme + " " + marker
    for scheme in AUTHORIZATION_SCHEMES
    for marker in (
        "[REDACTED_TOKEN]" + CANARY,
        "[REDACTED_TOKEN=" + CANARY + "]",
    )
)

REJECTION_CASES = JOINER_CASES + ASSIGNMENT_PREFIXES + MALFORMED_MARKERS


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
def test_unicode_cross_format_redaction(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    credential: str,
    expected: str,
) -> None:
    message = f"Database failure; {credential}"

    payload = make_payload(
        source_format,
        escaped,
        message,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    assert normalized.entries[0].message == message

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entry_count == 1
    assert sanitized.source_format == source_format
    assert sanitized.payload_bytes == len(payload)
    assert sanitized.redaction_count == 1

    entry = sanitized.entries[0]

    assert entry.position == 1
    assert entry.redaction_count == 1
    assert entry.message == f"Database failure; {expected}"
    assert CANARY not in entry.message

    validate_outbound_text(
        entry.message,
        settings.log_max_message_chars,
    )


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "message",
    REJECTION_CASES,
)
def test_unicode_rejected_before_persistence(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    message: str,
) -> None:
    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    payload = make_payload(
        source_format,
        escaped,
        message,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        service.ingest(
            uuid4(),
            payload,
            source_format,
        )

    assert CANARY not in str(captured.value)

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "control",
    UNSUPPORTED_CONTROLS,
)
def test_unicode_control_rejected_before_persistence(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    control: str,
) -> None:
    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    message = "Service" + control + "unavailable"

    with pytest.raises(InvalidLogEncodingError) as captured:
        service.ingest(
            uuid4(),
            make_payload(
                source_format,
                escaped,
                message,
            ),
            source_format,
        )

    assert message not in str(captured.value)

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "value",
    INTERNATIONAL_TEXT,
)
def test_unicode_cross_format_preservation(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    value: str,
) -> None:
    message = f"Service {value} unavailable."

    payload = make_payload(
        source_format,
        escaped,
        message,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert normalized.entries[0].message == message
    assert sanitized.entries[0].message == message
    assert sanitized.entry_count == 1
    assert sanitized.redaction_count == 0
    assert sanitized.payload_bytes == len(payload)

    validate_outbound_text(
        message,
        settings.log_max_message_chars,
    )


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
def test_unicode_multiple_redaction_accounting(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
) -> None:
    selected = (
        REDACTION_CASES[0],
        REDACTION_CASES[24],
        REDACTION_CASES[-1],
    )

    message = "Database failure; " + "; ".join(
        credential for credential, expected in selected
    )

    expected_message = "Database failure; " + "; ".join(
        expected for credential, expected in selected
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        make_payload(
            source_format,
            escaped,
            message,
        ),
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entry_count == 1
    assert sanitized.redaction_count == 3
    assert sanitized.entries[0].redaction_count == 3
    assert sanitized.entries[0].message == expected_message
    assert CANARY not in sanitized.entries[0].message

    validate_outbound_text(
        sanitized.entries[0].message,
        settings.log_max_message_chars,
    )
