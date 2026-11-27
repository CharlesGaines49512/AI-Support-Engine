from unittest.mock import MagicMock
from uuid import uuid4

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

CANARY = "SYNTHETIC_INTERNATIONAL_TEXT_CANARY"

LINE_ENDINGS = ("\n", "\r\n", "\r")

PRESERVATION_VALUES = (
    "\u63a5\u7d9a\u5931\u6557",
    "\u30b5\u30fc\u30d3\u30b9",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\uff33\uff45\uff52\uff56\uff49\uff43\uff45",
    "caf\u00e9",
    "cafe\u0301",
    "\u0645\u0631\u062d\u0628\u0627",
    "\u05e9\u05dc\u05d5\u05dd",
    "\u041e\u0448\u0438\u0431\u043a\u0430",
    "\ud55c\uad6d\uc5b4",
    "Service\u00a0Unavailable",
    "Service\u3000Unavailable",
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

UNSAFE_VALUES = (
    tuple(
        prefix[0] + joiner + prefix[1:] + CANARY
        for prefix in PREFIXES
        for joiner in ("\u200c", "\u200d")
    )
    + PREFIXES
    + (
        "B\u200dearer " + CANARY,
        "B\u200casic " + CANARY,
    )
)

UNSUPPORTED_CONTROLS = (
    "\u00ad",
    "\u061c",
    "\u200b",
    "\u202e",
    "\u2060",
    "\ufeff",
)


@pytest.mark.parametrize("value", PRESERVATION_VALUES)
@pytest.mark.parametrize("line_ending", LINE_ENDINGS)
@pytest.mark.parametrize("indentation", ("    ", "\t"))
def test_international_text_preservation(
    settings: Settings,
    value: str,
    line_ending: str,
    indentation: str,
) -> None:
    payload = line_ending.join(
        (
            f"2026-11-26T15:30:00Z ERROR [{value}] Database failed.",
            indentation + value,
            f"INFO [{value}] Retry completed.",
        )
    ).encode()

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    assert normalized.entries[0].service_name == value
    assert normalized.entries[1].service_name == value

    assert normalized.entries[0].message == ("Database failed.\n" + value)

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.source_format == LogFormat.TEXT
    assert sanitized.payload_bytes == len(payload)
    assert sanitized.entry_count == 2
    assert sanitized.redaction_count == 0

    first, second = sanitized.entries

    assert first.position == 1
    assert second.position == 2

    assert first.original_severity == "ERROR"
    assert second.original_severity == "INFO"

    assert first.service_name == value
    assert second.service_name == value

    assert first.message == "Database failed.\n" + value
    assert second.message == "Retry completed."

    for entry in sanitized.entries:
        assert entry.redaction_count == 0
        assert entry.exception is None
        assert entry.error_code is None
        assert entry.correlation_id is None

    validate_outbound_text(
        first.message,
        settings.log_max_message_chars,
    )

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )


@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
@pytest.mark.parametrize("line_ending", LINE_ENDINGS)
def test_international_text_service_name_redaction(
    settings: Settings,
    credential: str,
    expected: str,
    line_ending: str,
) -> None:
    payload = line_ending.join(
        (
            f"ERROR [{credential}] Database failed.",
            "    Additional diagnostic information.",
            "INFO [healthy-service] Retry completed.",
        )
    ).encode()

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    assert normalized.entries[0].service_name == credential

    sanitized = LogSanitizer(settings).sanitize(normalized)

    first, second = sanitized.entries

    assert sanitized.entry_count == 2
    assert sanitized.payload_bytes == len(payload)
    assert sanitized.redaction_count == 1

    assert first.service_name == expected

    assert first.message == ("Database failed.\nAdditional diagnostic information.")

    assert first.redaction_count == 1
    assert second.redaction_count == 0
    assert second.service_name == "healthy-service"

    assert CANARY not in repr(sanitized)

    validate_outbound_text(
        expected,
        settings.log_max_metadata_chars,
    )


@pytest.mark.parametrize("value", UNSAFE_VALUES)
@pytest.mark.parametrize("line_ending", LINE_ENDINGS)
def test_international_text_unsafe_metadata_rejected(
    settings: Settings,
    value: str,
    line_ending: str,
) -> None:
    payload = line_ending.join(
        (
            f"ERROR [{value}] Database failed.",
            "INFO Retry completed.",
        )
    ).encode()

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    assert normalized.entries[0].service_name == value

    factory = MagicMock()

    service = LogIngestionService(
        session_factory=factory,
        settings=settings,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        service.ingest(
            uuid4(),
            payload,
            LogFormat.TEXT,
        )

    assert CANARY not in str(captured.value)
    factory.assert_not_called()


@pytest.mark.parametrize("control", UNSUPPORTED_CONTROLS)
@pytest.mark.parametrize("line_ending", LINE_ENDINGS)
def test_international_text_unsafe_control_rejected(
    settings: Settings,
    control: str,
    line_ending: str,
) -> None:
    value = "Service" + control + "Unavailable"

    payload = line_ending.join(
        (
            f"ERROR [{value}] Database failed.",
            "INFO Retry completed.",
        )
    ).encode()

    factory = MagicMock()

    service = LogIngestionService(
        session_factory=factory,
        settings=settings,
    )

    with pytest.raises(InvalidLogEncodingError) as captured:
        service.ingest(
            uuid4(),
            payload,
            LogFormat.TEXT,
        )

    assert value not in str(captured.value)
    factory.assert_not_called()


@pytest.mark.parametrize(
    ("credential", "expected"),
    REDACTION_CASES,
)
@pytest.mark.parametrize("line_ending", LINE_ENDINGS)
def test_international_text_combined_redaction_accounting(
    settings: Settings,
    credential: str,
    expected: str,
    line_ending: str,
) -> None:
    payload = line_ending.join(
        (
            f"ERROR [{credential}] Database failed; {credential}",
            "    " + credential,
            "INFO [healthy-service] Retry completed.",
        )
    ).encode()

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    first, second = sanitized.entries

    assert sanitized.entry_count == 2
    assert sanitized.redaction_count == 3

    assert first.service_name == expected

    assert first.message == ("Database failed; " + expected + "\n" + expected)

    assert first.redaction_count == 3
    assert second.redaction_count == 0

    assert second.service_name == "healthy-service"
    assert second.message == "Retry completed."

    assert CANARY not in repr(sanitized)

    validate_outbound_text(
        first.message,
        settings.log_max_message_chars,
    )

    validate_outbound_text(
        expected,
        settings.log_max_metadata_chars,
    )
