import json
from unittest.mock import MagicMock
from uuid import uuid4
from xml.sax.saxutils import escape

import pytest

from app.core.config import Settings
from app.models.log_enums import LogFormat
from app.parsers.exceptions import UnsafeLogContentError
from app.security.sanitizer import SanitizationResult
from app.services.log_ingestion import LogIngestionService

CANARY = "SYNTHETIC_UNICODE_RESIDUAL_CANARY"

ENCODINGS = (
    (LogFormat.TEXT, False),
    (LogFormat.JSON, False),
    (LogFormat.JSON, True),
    (LogFormat.XML, False),
    (LogFormat.XML, True),
)

STRUCTURED_ENCODINGS = (
    (LogFormat.JSON, False),
    (LogFormat.JSON, True),
    (LogFormat.XML, False),
    (LogFormat.XML, True),
)

FIELDS = (
    "severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


CREDENTIALS = (
    fullwidth("password") + "\uff1a" + CANARY,
    fullwidth("api") + "_\u00a0" + fullwidth("key") + "\ufe66" + CANARY,
    fullwidth("access") + "\uff3f\u3000" + fullwidth("token") + "\ufe55" + CANARY,
    fullwidth("client_secret") + "\uff1d" + CANARY,
    "secret-\u2003_key=" + CANARY,
    fullwidth("refresh_token") + ":" + CANARY,
    fullwidth("Bearer") + "\u3000" + CANARY,
    fullwidth("Basic") + "\u00a0" + CANARY,
    "B\uff45arer\u2003" + CANARY,
    "B\uff41sic\u202f" + CANARY,
)

PRESERVATION_VALUES = (
    "\u63a5\u7d9a\u5931\u6557",
    "\u670d\u52a1\u4e0d\u53ef\u7528",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0915\u094d\u200d\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\uff33\uff45\uff52\uff56\uff49\uff43\uff45",
)


def xml_value(value: str, escaped: bool) -> str:
    if not escaped:
        return escape(value)

    return "".join(
        f"&#x{ord(character):x};" if ord(character) > 127 else escape(character)
        for character in value
    )


def make_payload(
    source_format: LogFormat,
    escaped: bool,
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

    if source_format == LogFormat.XML:
        children = "".join(
            f"<{name}>" + xml_value(content, escaped) + f"</{name}>"
            for name, content in fields.items()
        )

        return f"<entry>{children}</entry>".encode()

    assert field == "message"

    return f"ERROR {value}".encode()


@pytest.mark.parametrize("reported_count", (0, 1))
@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize("credential", CREDENTIALS)
def test_residual_unicode_message_rejected(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    reported_count: int,
    source_format: LogFormat,
    escaped: bool,
    credential: str,
) -> None:
    sanitizer_calls: list[str] = []

    def faulty_sanitizer(value: str) -> SanitizationResult:
        sanitizer_calls.append(value)

        return SanitizationResult(
            text=value,
            redaction_count=reported_count,
        )

    monkeypatch.setattr(
        "app.logs.sanitizer.sanitize_text",
        faulty_sanitizer,
    )

    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    message = "Database failure; " + credential

    payload = make_payload(
        source_format,
        escaped,
        "message",
        message,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        service.ingest(
            uuid4(),
            payload,
            source_format,
        )

    assert message in sanitizer_calls
    assert CANARY not in str(captured.value)
    assert str(captured.value) == ("Sanitized log field contains unsafe content.")

    session_factory.assert_not_called()


@pytest.mark.parametrize("reported_count", (0, 1))
@pytest.mark.parametrize(
    ("source_format", "escaped"),
    STRUCTURED_ENCODINGS,
)
@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("credential", CREDENTIALS)
def test_residual_unicode_metadata_rejected(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    reported_count: int,
    source_format: LogFormat,
    escaped: bool,
    field: str,
    credential: str,
) -> None:
    sanitizer_calls: list[str] = []

    def faulty_sanitizer(value: str) -> SanitizationResult:
        sanitizer_calls.append(value)

        return SanitizationResult(
            text=value,
            redaction_count=reported_count,
        )

    monkeypatch.setattr(
        "app.logs.sanitizer.sanitize_text",
        faulty_sanitizer,
    )

    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    payload = make_payload(
        source_format,
        escaped,
        field,
        credential,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        service.ingest(
            uuid4(),
            payload,
            source_format,
        )

    assert credential in sanitizer_calls
    assert CANARY not in str(captured.value)
    assert str(captured.value) == ("Sanitized log field contains unsafe content.")

    session_factory.assert_not_called()


@pytest.mark.parametrize("reported_count", (0, 1))
@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize("credential", CREDENTIALS)
def test_residual_unicode_source_name_rejected(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    reported_count: int,
    source_format: LogFormat,
    escaped: bool,
    credential: str,
) -> None:
    sanitizer_calls: list[str] = []

    def faulty_sanitizer(value: str) -> SanitizationResult:
        sanitizer_calls.append(value)

        return SanitizationResult(
            text=value,
            redaction_count=reported_count,
        )

    monkeypatch.setattr(
        "app.logs.sanitizer.sanitize_text",
        faulty_sanitizer,
    )

    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    payload = make_payload(
        source_format,
        escaped,
        "message",
        "Database connection failed.",
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        service.ingest(
            uuid4(),
            payload,
            source_format,
            source_name=credential,
        )

    assert credential in sanitizer_calls
    assert CANARY not in str(captured.value)
    assert str(captured.value) == ("Sanitized log field contains unsafe content.")

    session_factory.assert_not_called()


@pytest.mark.parametrize(
    ("source_format", "escaped"),
    ENCODINGS,
)
@pytest.mark.parametrize(
    "value",
    PRESERVATION_VALUES,
)
def test_safe_unicode_with_passthrough_sanitizer(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    source_format: LogFormat,
    escaped: bool,
    value: str,
) -> None:
    from app.logs.normalizer import LogNormalizer
    from app.logs.sanitizer import LogSanitizer

    def passthrough(value: str) -> SanitizationResult:
        return SanitizationResult(
            text=value,
            redaction_count=0,
        )

    monkeypatch.setattr(
        "app.logs.sanitizer.sanitize_text",
        passthrough,
    )

    message = f"Service {value} unavailable."

    payload = make_payload(
        source_format,
        escaped,
        "message",
        message,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entry_count == 1
    assert sanitized.redaction_count == 0
    assert sanitized.entries[0].redaction_count == 0
    assert sanitized.entries[0].message == message
