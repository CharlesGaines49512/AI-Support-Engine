import json
from unittest.mock import MagicMock
from uuid import uuid4
from xml.sax.saxutils import escape

import pytest

from app.core.config import Settings
from app.logs.normalizer import LogNormalizer
from app.logs.outbound_security import (
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat
from app.parsers.exceptions import UnsafeLogContentError
from app.services.log_ingestion import LogIngestionService

CANARY = "SYNTHETIC_CREDENTIAL_ACCEPTANCE_CANARY"

FORMATS = (
    LogFormat.TEXT,
    LogFormat.JSON,
    LogFormat.XML,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


def make_payload(
    source_format: LogFormat,
    message: str,
) -> bytes:
    if source_format == LogFormat.JSON:
        return json.dumps(
            {
                "severity": "ERROR",
                "message": message,
            }
        ).encode("utf-8")

    if source_format == LogFormat.XML:
        return (
            f'<entry severity="ERROR"><message>{escape(message)}</message></entry>'
        ).encode()

    return f"ERROR {message}".encode()


@pytest.mark.parametrize("source_format", FORMATS)
@pytest.mark.parametrize(
    ("credential", "expected"),
    [
        (
            f"password={CANARY}",
            "password=[REDACTED_SECRET]",
        ),
        (
            f"API KEY: {CANARY}",
            "API KEY: [REDACTED_SECRET]",
        ),
        (
            f"secret key={CANARY}",
            "secret key=[REDACTED_SECRET]",
        ),
        (
            f"access token={CANARY}",
            "access token=[REDACTED_SECRET]",
        ),
        (
            f"Authorization: Bearer {CANARY}",
            "Authorization: Bearer [REDACTED_TOKEN]",
        ),
        (
            f"Authorization: Basic {CANARY}",
            "Authorization: Basic [REDACTED_TOKEN]",
        ),
        (
            f"postgresql://user:{CANARY}@localhost/db",
            "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        ),
        (
            "user@example.com",
            "[REDACTED_EMAIL]",
        ),
    ],
)
def test_credential_pipeline_acceptance(
    settings: Settings,
    source_format: LogFormat,
    credential: str,
    expected: str,
) -> None:
    message = f"Database connection failed; {credential}"

    payload = make_payload(
        source_format,
        message,
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entry_count == 1
    assert sanitized.source_format == source_format
    assert sanitized.payload_bytes == len(payload)
    assert sanitized.redaction_count == 1

    entry = sanitized.entries[0]

    assert CANARY not in entry.message
    assert credential not in entry.message
    assert expected in entry.message
    assert "Database connection failed" in entry.message

    validate_outbound_text(
        entry.message,
        settings.log_max_message_chars,
    )


@pytest.mark.parametrize("source_format", FORMATS)
@pytest.mark.parametrize(
    "message",
    [
        f"Bearer [REDACTED_TOKEN]{CANARY}",
        f"Basic [REDACTED_TOKEN]{CANARY}",
        f"Bearer [REDACTED_TOKEN={CANARY}]",
        f"Basic [REDACTED_TOKEN={CANARY}]",
    ],
)
def test_malformed_authorization_rejected_before_persistence(
    settings: Settings,
    source_format: LogFormat,
    message: str,
) -> None:
    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    payload = make_payload(
        source_format,
        message,
    )

    with pytest.raises(UnsafeLogContentError) as error:
        service.ingest(
            uuid4(),
            payload,
            source_format,
        )

    assert CANARY not in str(error.value)

    session_factory.assert_not_called()


@pytest.mark.parametrize("source_format", FORMATS)
def test_multiple_credentials_safely_redacted(
    settings: Settings,
    source_format: LogFormat,
) -> None:
    message = (
        f"Database connection failed; password={CANARY}; "
        f"api key={CANARY}; "
        f"secret key={CANARY}; "
        f"Authorization: Bearer {CANARY}"
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        make_payload(source_format, message),
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    entry = sanitized.entries[0]

    assert CANARY not in entry.message
    assert entry.redaction_count == 4
    assert sanitized.redaction_count == 4

    assert "Database connection failed" in entry.message
    assert "password=[REDACTED_SECRET]" in entry.message
    assert "api key=[REDACTED_SECRET]" in entry.message
    assert "secret key=[REDACTED_SECRET]" in entry.message
    assert "Bearer [REDACTED_TOKEN]" in entry.message

    validate_outbound_text(
        entry.message,
        settings.log_max_message_chars,
    )


@pytest.mark.parametrize("source_format", FORMATS)
@pytest.mark.parametrize(
    "message",
    [
        "Database connection failed.",
        "Password reset completed.",
        "API key rotation completed.",
        "Access token expired.",
        "Client secret rotation scheduled.",
    ],
)
def test_safe_diagnostic_pipeline_preserved(
    settings: Settings,
    source_format: LogFormat,
    message: str,
) -> None:
    normalized = LogNormalizer(settings).parse_and_normalize(
        make_payload(source_format, message),
        source_format,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entry_count == 1
    assert sanitized.redaction_count == 0

    assert sanitized.entries[0].message == (normalized.entries[0].message)

    assert message in sanitized.entries[0].message

    validate_outbound_text(
        sanitized.entries[0].message,
        settings.log_max_message_chars,
    )
