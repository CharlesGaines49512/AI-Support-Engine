import json
from dataclasses import replace
from typing import Any, cast
from xml.sax.saxutils import escape

import pytest

from app.core.config import Settings
from app.logs.contracts import NormalizedLog, NormalizedLogEntry
from app.logs.normalizer import LogNormalizer
from app.logs.outbound_security import validate_outbound_text
from app.logs.sanitizer import LogSanitizer
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.exceptions import UnsafeLogContentError
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_ADVERSARIAL_REDACTION_CANARY"

LABELS = (
    "password",
    "passwd",
    "pwd",
    "api_key",
    "api-key",
    "api key",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret_key",
    "secret key",
    "token",
    "secret",
)

FIELDS = (
    "message",
    "original_severity",
    "service_name",
    "exception",
    "error_code",
    "correlation_id",
)

VALID_SUFFIXES = (
    "",
    "; status=failed",
    ", status=failed",
    " status=failed",
    "}",
    "]",
    "&status=failed",
)

MALFORMED_SUFFIXES = (
    CANARY,
    "-" + CANARY,
    "_" + CANARY,
    "]" + CANARY,
)

RAW_CREDENTIALS = (
    f"password={CANARY}",
    f"api key={CANARY}",
    f"secret key={CANARY}",
    f"Authorization: Bearer {CANARY}",
    f"Authorization: Basic {CANARY}",
    f"postgresql://user:{CANARY}@localhost/db",
    "synthetic@example.com",
    "sk-" + "a" * 32,
    "ghp_" + "b" * 36,
    "xoxb-" + "c" * 24,
    "AKIA" + "D" * 16,
    "eyJabc123.payload123.signature123",
    f'password="{CANARY}"',
    f"passwd='{CANARY}'",
)


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None).model_copy(
        update={
            "log_max_payload_bytes": 8192,
            "log_max_entries": 10,
            "log_max_message_chars": 1000,
            "log_max_metadata_chars": 200,
        }
    )


@pytest.fixture
def sanitizer(settings: Settings) -> LogSanitizer:
    return LogSanitizer(settings)


def make_log(
    field: str,
    value: str,
) -> NormalizedLog:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.ERROR,
        message="Database connection failed.",
    )

    entry = replace(entry, **cast(dict[str, Any], {field: value}))

    return NormalizedLog(
        source_format=LogFormat.TEXT,
        payload_bytes=100,
        entries=(entry,),
    )


@pytest.mark.parametrize("label", LABELS)
@pytest.mark.parametrize("suffix", VALID_SUFFIXES)
def test_valid_assignment_marker_is_unchanged(
    label: str,
    suffix: str,
) -> None:
    value = f"{label}=[REDACTED_SECRET]{suffix}"

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0
    assert result.was_modified is False


@pytest.mark.parametrize("label", LABELS)
@pytest.mark.parametrize("suffix", MALFORMED_SUFFIXES)
def test_malformed_assignment_suffix_removed(
    label: str,
    suffix: str,
) -> None:
    value = f"{label}=[REDACTED_SECRET]{suffix}"

    result = sanitize_text(value)

    assert CANARY not in result.text
    assert result.redaction_count > 0

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize("credential", RAW_CREDENTIALS)
def test_redaction_is_idempotent(
    credential: str,
) -> None:
    first = sanitize_text(credential)
    second = sanitize_text(first.text)
    third = sanitize_text(second.text)

    assert first.redaction_count > 0

    assert second.text == first.text
    assert second.redaction_count == 0

    assert third.text == first.text
    assert third.redaction_count == 0

    assert CANARY not in third.text


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize(
    "value",
    (
        "password=[REDACTED_SECRET]",
        "api key=[REDACTED_SECRET]",
        "secret key=[REDACTED_SECRET]",
        "Bearer [REDACTED_TOKEN]",
        "Basic [REDACTED_TOKEN]",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
    ),
)
def test_log_sanitizer_preserves_existing_markers(
    sanitizer: LogSanitizer,
    field: str,
    value: str,
) -> None:
    result = sanitizer.sanitize(make_log(field, value))

    entry = result.entries[0]

    assert getattr(entry, field) == value
    assert entry.redaction_count == 0
    assert result.redaction_count == 0


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize(
    "value",
    (
        f"password=[REDACTED_SECRET]{CANARY}",
        f"api key=[REDACTED_SECRET]-{CANARY}",
        f"secret key=[REDACTED_SECRET]_{CANARY}",
        f"password=[REDACTED_SECRET]]{CANARY}",
        f"password=[REDACTED_SECRET={CANARY}]",
        f"Bearer [REDACTED_TOKEN]{CANARY}",
        f"Basic [REDACTED_TOKEN]{CANARY}",
        f"Bearer [REDACTED_TOKEN={CANARY}]",
    ),
)
def test_real_sanitizer_prevents_residual_marker_secrets(
    sanitizer: LogSanitizer,
    field: str,
    value: str,
) -> None:
    try:
        result = sanitizer.sanitize(make_log(field, value))
    except UnsafeLogContentError as error:
        assert CANARY not in str(error)
        return

    sanitized = getattr(result.entries[0], field)

    assert isinstance(sanitized, str)
    assert CANARY not in sanitized

    validate_outbound_text(sanitized, 2000)


@pytest.mark.parametrize(
    "value",
    (
        "password=[REDACTED_SECRET]",
        "api key=[REDACTED_SECRET]",
        "secret key=[REDACTED_SECRET]",
        "Bearer [REDACTED_TOKEN]",
        "Basic [REDACTED_TOKEN]",
        "postgresql://[REDACTED_CREDENTIALS]@localhost/db",
    ),
)
def test_source_metadata_preserves_existing_markers(
    sanitizer: LogSanitizer,
    value: str,
) -> None:
    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


@pytest.mark.parametrize(
    "value",
    (
        f"password=[REDACTED_SECRET]{CANARY}",
        f"api key=[REDACTED_SECRET]-{CANARY}",
        f"secret key=[REDACTED_SECRET]_{CANARY}",
        f"password=[REDACTED_SECRET]]{CANARY}",
        f"password=[REDACTED_SECRET={CANARY}]",
        f"Bearer [REDACTED_TOKEN]{CANARY}",
        f"Basic [REDACTED_TOKEN]{CANARY}",
        f"Bearer [REDACTED_TOKEN={CANARY}]",
    ),
)
def test_source_metadata_rejects_or_removes_marker_secrets(
    sanitizer: LogSanitizer,
    value: str,
) -> None:
    try:
        sanitized, _ = sanitizer.sanitize_source_name(value)
    except UnsafeLogContentError as error:
        assert CANARY not in str(error)
        return

    assert sanitized is not None
    assert CANARY not in sanitized

    validate_outbound_text(sanitized, 2000)


@pytest.mark.parametrize("source_format", list(LogFormat))
@pytest.mark.parametrize(
    "value",
    (
        f"password=[REDACTED_SECRET]{CANARY}",
        f"api key=[REDACTED_SECRET]-{CANARY}",
        f"secret key=[REDACTED_SECRET]_{CANARY}",
        f"password=[REDACTED_SECRET]]{CANARY}",
        f"password=[REDACTED_SECRET={CANARY}]",
        f"Bearer [REDACTED_TOKEN]{CANARY}",
        f"Basic [REDACTED_TOKEN]{CANARY}",
        f"Bearer [REDACTED_TOKEN={CANARY}]",
    ),
)
def test_parser_pipeline_prevents_marker_secret_disclosure(
    settings: Settings,
    sanitizer: LogSanitizer,
    source_format: LogFormat,
    value: str,
) -> None:
    message = f"Database connection failed; {value}"

    if source_format == LogFormat.TEXT:
        payload = f"ERROR {message}".encode()
    elif source_format == LogFormat.JSON:
        payload = json.dumps(
            {
                "severity": "ERROR",
                "message": message,
            }
        ).encode()
    else:
        payload = (
            f'<entry severity="ERROR"><message>{escape(message)}</message></entry>'
        ).encode()

    try:
        normalized = LogNormalizer(settings).parse_and_normalize(
            payload,
            source_format,
        )

        result = sanitizer.sanitize(normalized)
    except UnsafeLogContentError as error:
        assert CANARY not in str(error)
        return

    assert result.entry_count == 1
    assert CANARY not in result.entries[0].message

    validate_outbound_text(
        result.entries[0].message,
        settings.log_max_message_chars,
    )


@pytest.mark.parametrize("label", LABELS)
def test_existing_marker_does_not_inflate_redaction_count(
    label: str,
) -> None:
    value = f"{label}=[REDACTED_SECRET]; password={CANARY}; status=failed"

    expected = f"{label}=[REDACTED_SECRET]; password=[REDACTED_SECRET]; status=failed"

    result = sanitize_text(value)

    assert result.text == expected
    assert result.redaction_count == 1
    assert CANARY not in result.text


HISTORICAL_MARKERS = (
    "password=[REDACTED_SECRET]",
    "api key=[REDACTED_SECRET]",
    "secret key=[REDACTED_SECRET]",
    "Bearer [REDACTED_TOKEN]",
    "Basic [REDACTED_TOKEN]",
)

HISTORICAL_UNSAFE_SUFFIXES = (
    CANARY,
    "-" + CANARY,
    "_" + CANARY,
    "]" + CANARY,
    "]]" + CANARY,
    "]]]" + CANARY,
)

HISTORICAL_SAFE_SUFFIXES = (
    "",
    "]",
    "]]",
    "; status=failed",
    ", status=failed",
    " status=failed",
    "}",
    "&status=failed",
)


@pytest.mark.parametrize("marker", HISTORICAL_MARKERS)
@pytest.mark.parametrize("suffix", HISTORICAL_UNSAFE_SUFFIXES)
def test_historical_marker_rejects_unsafe_suffix(
    marker: str,
    suffix: str,
) -> None:
    from app.logs.outbound_security import (
        UnsafeOutboundEvidenceError,
    )

    value = marker + suffix

    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("marker", HISTORICAL_MARKERS)
@pytest.mark.parametrize("suffix", HISTORICAL_SAFE_SUFFIXES)
def test_historical_marker_preserves_safe_boundaries(
    marker: str,
    suffix: str,
) -> None:
    value = marker + suffix

    validate_outbound_text(value, 2000)
