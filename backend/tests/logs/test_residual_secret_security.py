from dataclasses import replace
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.logs import sanitizer as sanitizer_module
from app.logs.contracts import (
    NormalizedLog,
    NormalizedLogEntry,
)
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.exceptions import UnsafeLogContentError
from app.security.sanitizer import SanitizationResult
from app.services.log_ingestion import LogIngestionService

CANARY = "SYNTHETIC_RESIDUAL_SECRET_CANARY"

FIELDS = (
    "message",
    "original_severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)

UNSAFE_VALUES = (
    f"password={CANARY}",
    f"api key={CANARY}",
    f"secret key={CANARY}",
    f"Bearer {CANARY}",
    f"password=[REDACTED_SECRET]{CANARY}",
    f"Bearer [REDACTED_TOKEN]{CANARY}",
    f"Authorization: Bearer [REDACTED_TOKEN={CANARY}]",
    f"postgresql://user:{CANARY}@localhost/db",
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


@pytest.fixture
def sanitizer(settings: Settings) -> LogSanitizer:
    return LogSanitizer(settings)


def incomplete_sanitization(
    value: str,
) -> SanitizationResult:
    return SanitizationResult(
        text=value,
        redaction_count=0,
    )


def make_log(
    **fields: Any,
) -> NormalizedLog:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message="Synthetic application failure.",
    )

    entry = replace(entry, **fields)

    return NormalizedLog(
        source_format=LogFormat.TEXT,
        payload_bytes=100,
        entries=(entry,),
    )


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_residual_sensitive_field_rejected(
    monkeypatch: pytest.MonkeyPatch,
    sanitizer: LogSanitizer,
    field: str,
    value: str,
) -> None:
    monkeypatch.setattr(
        sanitizer_module,
        "sanitize_text",
        incomplete_sanitization,
    )

    with pytest.raises(UnsafeLogContentError) as error:
        sanitizer.sanitize(make_log(**{field: value}))

    assert CANARY not in str(error.value)


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_residual_source_metadata_rejected(
    monkeypatch: pytest.MonkeyPatch,
    sanitizer: LogSanitizer,
    value: str,
) -> None:
    monkeypatch.setattr(
        sanitizer_module,
        "sanitize_text",
        incomplete_sanitization,
    )

    with pytest.raises(UnsafeLogContentError) as error:
        sanitizer.sanitize_source_name(value)

    assert CANARY not in str(error.value)


@pytest.mark.parametrize(
    "value",
    [
        "Application ready.",
        "Database connection failed.",
        "Password reset completed.",
        "API key rotation completed.",
        "Diagnostic message: caf\u00e9",
        "[REDACTED]",
        "[REDACTED_EMAIL]",
        "password=[REDACTED_SECRET]",
        "Bearer [REDACTED_TOKEN]",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
    ],
)
def test_safe_sanitizer_output_preserved(
    monkeypatch: pytest.MonkeyPatch,
    sanitizer: LogSanitizer,
    value: str,
) -> None:
    monkeypatch.setattr(
        sanitizer_module,
        "sanitize_text",
        incomplete_sanitization,
    )

    result = sanitizer.sanitize(make_log(message=value))

    assert result.entries[0].message == value
    assert result.redaction_count == 0


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        (
            f"password={CANARY}",
            "password=[REDACTED_SECRET]",
        ),
        (
            f"api key={CANARY}",
            "api key=[REDACTED_SECRET]",
        ),
        (
            f"secret key={CANARY}",
            "secret key=[REDACTED_SECRET]",
        ),
        (
            f"Bearer {CANARY}",
            "Bearer [REDACTED_TOKEN]",
        ),
        (
            f"postgresql://user:{CANARY}@localhost/db",
            "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
        ),
    ],
)
def test_normal_credential_redaction_preserved(
    sanitizer: LogSanitizer,
    original: str,
    expected: str,
) -> None:
    result = sanitizer.sanitize(make_log(message=original))

    assert result.entries[0].message == expected
    assert CANARY not in result.entries[0].message
    assert result.redaction_count == 1


@pytest.mark.parametrize(
    "location",
    ["message", "source_name"],
)
def test_residual_secret_prevents_database_access(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    location: str,
) -> None:
    session_factory = MagicMock()

    service = LogIngestionService(
        session_factory=session_factory,
        settings=settings,
    )

    monkeypatch.setattr(
        sanitizer_module,
        "sanitize_text",
        incomplete_sanitization,
    )

    if location == "message":
        payload = (f"ERROR password={CANARY}").encode()

        source_name = "application.log"
    else:
        payload = b"ERROR Database connection failed."

        source_name = f"password={CANARY}"

    with pytest.raises(UnsafeLogContentError) as error:
        service.ingest(
            uuid4(),
            payload,
            LogFormat.TEXT,
            source_name=source_name,
        )

    assert CANARY not in str(error.value)

    session_factory.assert_not_called()
