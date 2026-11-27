from dataclasses import replace

import pytest

from app.core.config import Settings
from app.logs.contracts import (
    NormalizedLog,
    NormalizedLogEntry,
)
from app.logs.normalizer import LogNormalizer
from app.logs.sanitizer import LogSanitizer
from app.logs.security import validate_sensitive_field
from app.models.log_enums import LogFormat, LogSeverity
from app.parsers.contracts import ParsedLog, ParsedLogEntry
from app.parsers.exceptions import (
    InvalidLogEncodingError,
    MalformedLogError,
    UnsafeLogContentError,
)

CANARY = "SYNTHETIC_SECRET_CANARY"


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


def make_entry(
    message: str,
    position: int = 1,
) -> NormalizedLogEntry:
    return NormalizedLogEntry(
        position=position,
        severity=LogSeverity.ERROR,
        message=message,
    )


def make_log(
    *entries: NormalizedLogEntry,
) -> NormalizedLog:
    return NormalizedLog(
        source_format=LogFormat.TEXT,
        payload_bytes=1000,
        entries=entries,
    )


@pytest.mark.parametrize(
    "message",
    [
        "Application ready",
        "Database connection failed",
        "Password reset completed",
        "Token expired",
        "Authorization request failed",
        "Basic application configuration loaded",
        "API key rotation completed",
        f"password={CANARY}",
        f"Authorization: Bearer {CANARY}",
    ],
)
def test_valid_field_security_validation(
    message: str,
) -> None:
    validate_sensitive_field(message)


@pytest.mark.parametrize(
    "message",
    [
        "password=",
        "password:",
        "passwd=",
        "pwd:",
        "api_key=",
        "api-key:",
        "api key:",
        "access_token=",
        "refresh_token:",
        "client_secret=",
        "secret=",
        "token:",
        "credential=",
        'password="',
        "password='",
        '"password":',
        "Authorization:",
        "Authorization: Bearer",
        "Authorization: Basic",
        "Bearer",
        "Basic",
        "password",
        "api_key",
        '"access_token"',
        "Application failure password=",
        "Request failed\npassword=",
    ],
)
def test_incomplete_credential_expressions_rejected(
    message: str,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        validate_sensitive_field(message)


@pytest.mark.parametrize(
    "message",
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----END RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ("-----BEGIN PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----"),
        ("-----BEGIN RSA PRIVATE KEY-----\n-----END PRIVATE KEY-----"),
        ("-----END PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----"),
    ],
)
def test_fragmented_private_key_boundaries_rejected(
    message: str,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        validate_sensitive_field(message)


def test_complete_private_key_redacted(
    sanitizer: LogSanitizer,
) -> None:
    message = f"-----BEGIN PRIVATE KEY-----\n{CANARY}\n-----END PRIVATE KEY-----"

    result = sanitizer.sanitize(make_log(make_entry(message)))

    assert CANARY not in result.entries[0].message
    assert result.redaction_count > 0


def test_multiple_complete_key_blocks_validated() -> None:
    message = (
        "-----BEGIN PRIVATE KEY-----\n"
        "Synthetic first key\n"
        "-----END PRIVATE KEY-----\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Synthetic second key\n"
        "-----END RSA PRIVATE KEY-----"
    )

    validate_sensitive_field(message)


def test_private_key_fragmented_across_events_rejected(
    sanitizer: LogSanitizer,
) -> None:
    source = make_log(
        make_entry("-----BEGIN PRIVATE KEY-----", 1),
        make_entry(CANARY, 2),
        make_entry("-----END PRIVATE KEY-----", 3),
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        sanitizer.sanitize(source)

    assert CANARY not in str(captured.value)


def test_private_key_fragmented_across_fields_rejected(
    sanitizer: LogSanitizer,
) -> None:
    source = replace(
        make_entry("-----BEGIN PRIVATE KEY-----"),
        exception=(f"{CANARY}\n-----END PRIVATE KEY-----"),
    )

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize(make_log(source))


def test_password_fragmented_across_events_rejected(
    sanitizer: LogSanitizer,
) -> None:
    source = make_log(
        make_entry("password=", 1),
        make_entry(CANARY, 2),
    )

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize(source)


def test_password_fragmented_across_fields_rejected(
    sanitizer: LogSanitizer,
) -> None:
    source = replace(
        make_entry("password="),
        exception=CANARY,
    )

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize(make_log(source))


@pytest.mark.parametrize(
    "character",
    [
        "\x00",
        "\x01",
        "\x08",
        "\x1b",
        "\x7f",
        "\u0085",
        "\u009f",
        "\ud800",
        "\udfff",
    ],
)
def test_invalid_normalized_characters_rejected(
    sanitizer: LogSanitizer,
    character: str,
) -> None:
    message = f"Synthetic{character}event"

    with pytest.raises(InvalidLogEncodingError):
        sanitizer.sanitize(make_log(make_entry(message)))


def test_invalid_metadata_characters_rejected(
    sanitizer: LogSanitizer,
) -> None:
    source = replace(
        make_entry("Ready"),
        service_name="Synthetic\x00service",
    )

    with pytest.raises(InvalidLogEncodingError):
        sanitizer.sanitize(make_log(source))


def test_escaped_json_password_redacted(
    settings: Settings,
    sanitizer: LogSanitizer,
) -> None:
    payload = b'{"message":"\\u0070assword=SYNTHETIC_SECRET_CANARY"}'

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.JSON,
    )

    result = sanitizer.sanitize(normalized)

    assert CANARY not in result.entries[0].message
    assert result.redaction_count > 0


def test_encoded_xml_password_redacted(
    settings: Settings,
    sanitizer: LogSanitizer,
) -> None:
    payload = (
        b"<entry><message>&#112;assword&#61;SYNTHETIC_SECRET_CANARY</message></entry>"
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.XML,
    )

    result = sanitizer.sanitize(normalized)

    assert CANARY not in result.entries[0].message
    assert result.redaction_count > 0


def test_plain_text_fragmented_private_key_rejected(
    settings: Settings,
    sanitizer: LogSanitizer,
) -> None:
    payload = (
        b"-----BEGIN PRIVATE KEY-----\n"
        b"SYNTHETIC_SECRET_CANARY\n"
        b"-----END PRIVATE KEY-----"
    )

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    assert normalized.entry_count == 3

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize(normalized)


@pytest.mark.parametrize(
    ("source_format", "payload"),
    [
        (
            LogFormat.XML,
            b'<entry message="Ready">'
            b"<password>SYNTHETIC_SECRET_CANARY</password>"
            b"</entry>",
        ),
        (
            LogFormat.XML,
            b'<entry message="Ready" password="SYNTHETIC_SECRET_CANARY"/>',
        ),
        (
            LogFormat.JSON,
            b'{"message":"Ready","password":"SYNTHETIC_SECRET_CANARY"}',
        ),
        (
            LogFormat.JSON,
            b'{"message":"Ready","credentials":{"token":"SYNTHETIC_SECRET_CANARY"}}',
        ),
    ],
)
def test_unsupported_credential_fields_rejected(
    settings: Settings,
    source_format: LogFormat,
    payload: bytes,
) -> None:
    with pytest.raises(MalformedLogError) as captured:
        LogNormalizer(settings).parse_and_normalize(
            payload,
            source_format,
        )

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "source_name",
    [None, "", " ", "\t\r\n"],
)
def test_empty_source_names_normalized(
    sanitizer: LogSanitizer,
    source_name: str | None,
) -> None:
    assert sanitizer.sanitize_source_name(source_name) == (None, 0)


def test_clean_source_name_preserved(
    sanitizer: LogSanitizer,
) -> None:
    assert sanitizer.sanitize_source_name("  ticketing-service  ") == (
        "ticketing-service",
        0,
    )


def test_sensitive_source_name_redacted(
    sanitizer: LogSanitizer,
) -> None:
    name, count = sanitizer.sanitize_source_name(f"password={CANARY}")

    assert name is not None
    assert CANARY not in name
    assert count > 0


def test_oversized_source_name_replaced(
    sanitizer: LogSanitizer,
) -> None:
    name, count = sanitizer.sanitize_source_name("x" * 201)

    assert name == "[REDACTED]"
    assert count == 1


def test_fragmented_source_name_rejected(
    sanitizer: LogSanitizer,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize_source_name("password=")


def test_invalid_source_name_rejected(
    sanitizer: LogSanitizer,
) -> None:
    with pytest.raises(InvalidLogEncodingError):
        sanitizer.sanitize_source_name("source\x00name")


def test_parsed_text_fields_hidden_from_repr() -> None:
    entry = ParsedLogEntry(
        position=1,
        message=CANARY,
        timestamp=CANARY,
        severity=CANARY,
        service_name=CANARY,
        exception=CANARY,
        error_code=CANARY,
        correlation_id=CANARY,
    )

    result = ParsedLog(
        source_format=LogFormat.JSON,
        payload_bytes=100,
        entries=(entry,),
    )

    assert CANARY not in repr(entry)
    assert CANARY not in repr(result)
    assert entry.message == CANARY


def test_normalized_text_fields_hidden_from_repr() -> None:
    entry = NormalizedLogEntry(
        position=1,
        severity=LogSeverity.UNKNOWN,
        message=CANARY,
        original_severity=CANARY,
        service_name=CANARY,
        exception=CANARY,
        error_code=CANARY,
        correlation_id=CANARY,
    )

    result = make_log(entry)

    assert CANARY not in repr(entry)
    assert CANARY not in repr(result)
    assert entry.message == CANARY


def test_security_error_does_not_expose_content() -> None:
    message = f"-----BEGIN PRIVATE KEY-----\n{CANARY}"

    with pytest.raises(UnsafeLogContentError) as captured:
        validate_sensitive_field(message)

    assert CANARY not in str(captured.value)


def test_sanitizer_recovery_after_security_rejection(
    sanitizer: LogSanitizer,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize(make_log(make_entry("password=")))

    result = sanitizer.sanitize(make_log(make_entry("Recovered")))

    assert result.entry_count == 1
    assert result.entries[0].message == "Recovered"
    assert result.redaction_count == 0
