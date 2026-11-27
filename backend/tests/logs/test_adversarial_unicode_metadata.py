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

CANARY = "SYNTHETIC_UNICODE_METADATA_CANARY"

STRUCTURED_ENCODINGS = (
    (LogFormat.JSON, False, False),
    (LogFormat.JSON, True, False),
    (LogFormat.XML, False, False),
    (LogFormat.XML, True, False),
    (LogFormat.XML, False, True),
    (LogFormat.XML, True, True),
)

FIELDS = (
    ("severity", "original_severity"),
    ("service_name", "service_name"),
    ("exception", "exception"),
    ("error_code", "error_code"),
    ("correlation_id", "correlation_id"),
)

FORMATS = (
    LogFormat.TEXT,
    LogFormat.JSON,
    LogFormat.XML,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


PREFIXES = (
    fullwidth("password") + "\uff1a",
    fullwidth("api") + "_\u00a0" + fullwidth("key") + "\ufe66",
    fullwidth("access") + "\uff3f\u3000" + fullwidth("token") + "\ufe55",
    fullwidth("client_secret") + "\uff1d",
    "secret-\u2003_key=",
    fullwidth("refresh_token") + ":",
)

REDACTION_CASES = tuple(
    (
        prefix + CANARY,
        prefix + "[REDACTED_SECRET]",
    )
    for prefix in PREFIXES
) + tuple(
    (
        scheme + "\u3000" + CANARY,
        scheme + " [REDACTED_TOKEN]",
    )
    for scheme in (
        fullwidth("Bearer"),
        fullwidth("Basic"),
        "B\uff45arer",
        "B\uff41sic",
    )
)

UNSAFE_CASES = (
    tuple(
        prefix[0] + joiner + prefix[1:] + CANARY
        for prefix in PREFIXES
        for joiner in ("\u200c", "\u200d")
    )
    + PREFIXES
    + (
        fullwidth("Bearer") + " [REDACTED_TOKEN]" + CANARY,
        fullwidth("Basic") + " [REDACTED_TOKEN=" + CANARY + "]",
    )
)

CONTROL_CASES = (
    "\u00ad",
    "\u061c",
    "\u200b",
    "\u202e",
    "\u2060",
    "\ufeff",
)

PRESERVATION_CASES = (
    "\u63a5\u7d9a\u5931\u6557",
    "\u670d\u52a1\u4e0d\u53ef\u7528",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\uff33\uff45\uff52\uff56\uff49\uff43\uff45",
)


def xml_value(value: str, escaped: bool) -> str:
    if escaped:
        return "".join(
            f"&#x{ord(character):x};"
            if ord(character) > 127
            else escape(
                character,
                {'"': "&quot;"},
            )
            for character in value
        )

    return escape(value, {'"': "&quot;"})


def make_structured_payload(
    source_format: LogFormat,
    escaped: bool,
    attributes: bool,
    field: str,
    value: str,
) -> bytes:
    fields = {
        "severity": "ERROR",
        "message": "Database connection failed.",
    }

    fields[field] = value

    if source_format == LogFormat.JSON:
        return json.dumps(
            fields,
            ensure_ascii=escaped,
        ).encode()

    if attributes:
        attributes_text = " ".join(
            f'{name}="{xml_value(content, escaped)}"'
            for name, content in fields.items()
        )

        return f"<entry {attributes_text}/>".encode()

    children = "".join(
        f"<{name}>" + xml_value(content, escaped) + f"</{name}>"
        for name, content in fields.items()
    )

    return f"<entry>{children}</entry>".encode()


def make_safe_payload(
    source_format: LogFormat,
) -> bytes:
    if source_format == LogFormat.JSON:
        return b'{"severity":"ERROR","message":"Database failed."}'

    if source_format == LogFormat.XML:
        return b'<entry severity="ERROR"><message>Database failed.</message></entry>'

    return b"ERROR Database failed."


@pytest.mark.parametrize(
    ("source_format", "escaped", "attributes"),
    STRUCTURED_ENCODINGS,
)
@pytest.mark.parametrize(
    ("input_field", "output_field"),
    FIELDS,
)
@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
def test_structured_metadata_redaction(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    attributes: bool,
    input_field: str,
    output_field: str,
    credential: str,
    expected: str,
) -> None:
    payload = make_structured_payload(
        source_format,
        escaped,
        attributes,
        input_field,
        credential,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    assert (
        getattr(
            normalized.entries[0],
            output_field,
        )
        == credential
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    entry = sanitized.entries[0]

    assert sanitized.entry_count == 1
    assert sanitized.source_format == source_format
    assert sanitized.payload_bytes == len(payload)
    assert sanitized.redaction_count == 1
    assert entry.redaction_count == 1

    assert entry.message == "Database connection failed."

    value = getattr(entry, output_field)

    assert value == expected
    assert CANARY not in value
    assert CANARY not in repr(sanitized)

    limit = (
        settings.log_max_message_chars
        if input_field == "exception"
        else settings.log_max_metadata_chars
    )

    validate_outbound_text(value, limit)


@pytest.mark.parametrize(
    ("source_format", "escaped", "attributes"),
    STRUCTURED_ENCODINGS,
)
@pytest.mark.parametrize(
    ("input_field", "output_field"),
    FIELDS,
)
@pytest.mark.parametrize("value", UNSAFE_CASES)
def test_structured_metadata_rejection(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    attributes: bool,
    input_field: str,
    output_field: str,
    value: str,
) -> None:
    payload = make_structured_payload(
        source_format,
        escaped,
        attributes,
        input_field,
        value,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    assert (
        getattr(
            normalized.entries[0],
            output_field,
        )
        == value
    )

    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
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
    ("source_format", "escaped", "attributes"),
    STRUCTURED_ENCODINGS,
)
@pytest.mark.parametrize(
    ("input_field", "output_field"),
    FIELDS,
)
@pytest.mark.parametrize("control", CONTROL_CASES)
def test_structured_metadata_control_rejection(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    attributes: bool,
    input_field: str,
    output_field: str,
    control: str,
) -> None:
    value = "Service" + control + "unavailable"

    payload = make_structured_payload(
        source_format,
        escaped,
        attributes,
        input_field,
        value,
    )

    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    with pytest.raises(InvalidLogEncodingError) as captured:
        service.ingest(
            uuid4(),
            payload,
            source_format,
        )

    assert value not in str(captured.value)
    assert output_field

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    ("source_format", "escaped", "attributes"),
    STRUCTURED_ENCODINGS,
)
@pytest.mark.parametrize(
    ("input_field", "output_field"),
    FIELDS,
)
@pytest.mark.parametrize(
    "value",
    PRESERVATION_CASES,
)
def test_structured_metadata_preservation(
    settings: Settings,
    source_format: LogFormat,
    escaped: bool,
    attributes: bool,
    input_field: str,
    output_field: str,
    value: str,
) -> None:
    payload = make_structured_payload(
        source_format,
        escaped,
        attributes,
        input_field,
        value,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    assert (
        getattr(
            normalized.entries[0],
            output_field,
        )
        == value
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entry_count == 1
    assert sanitized.redaction_count == 0
    assert sanitized.entries[0].redaction_count == 0

    assert (
        getattr(
            sanitized.entries[0],
            output_field,
        )
        == value
    )

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )


@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
def test_unicode_source_name_redaction(
    settings: Settings,
    credential: str,
    expected: str,
) -> None:
    value, count = LogSanitizer(settings).sanitize_source_name(credential)

    assert value == expected
    assert count == 1
    assert CANARY not in value

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )


@pytest.mark.parametrize("source_format", FORMATS)
@pytest.mark.parametrize("value", UNSAFE_CASES)
def test_unicode_source_name_rejection(
    settings: Settings,
    source_format: LogFormat,
    value: str,
) -> None:
    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        service.ingest(
            uuid4(),
            make_safe_payload(source_format),
            source_format,
            source_name=value,
        )

    assert CANARY not in str(captured.value)

    session_factory.assert_not_called()


@pytest.mark.parametrize("source_format", FORMATS)
@pytest.mark.parametrize("control", CONTROL_CASES)
def test_unicode_source_name_control_rejection(
    settings: Settings,
    source_format: LogFormat,
    control: str,
) -> None:
    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    value = "Service" + control + "unavailable"

    with pytest.raises(InvalidLogEncodingError) as captured:
        service.ingest(
            uuid4(),
            make_safe_payload(source_format),
            source_format,
            source_name=value,
        )

    assert value not in str(captured.value)

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    "value",
    PRESERVATION_CASES,
)
def test_unicode_source_name_preservation(
    settings: Settings,
    value: str,
) -> None:
    sanitized, count = LogSanitizer(settings).sanitize_source_name(value)

    assert sanitized == value
    assert count == 0

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )
