import json

import pytest

from app.core.config import Settings
from app.logs.normalizer import LogNormalizer
from app.logs.sanitizer import LogSanitizer
from app.logs.security import validate_sensitive_field
from app.models.log_enums import LogFormat
from app.parsers.exceptions import UnsafeLogContentError

CANARY = "SYNTHETIC_FRAGMENTED_SECRET_CANARY"


@pytest.mark.parametrize(
    "newline",
    ["\n", "\r\n", "\r"],
)
@pytest.mark.parametrize(
    "prefix",
    [
        "password=",
        "api_key:",
        "access_token=",
        "client_secret:",
        "Authorization: Bearer",
        "Authorization: Basic",
    ],
)
def test_fragmented_credentials_rejected(
    newline: str,
    prefix: str,
) -> None:
    message = f"{prefix}{newline}{CANARY}"

    with pytest.raises(UnsafeLogContentError) as captured:
        validate_sensitive_field(message)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "newline",
    ["\n", "\r\n", "\r"],
)
def test_clean_multiline_fields_allowed(
    newline: str,
) -> None:
    message = f"Application failure{newline}Additional diagnostic details"

    validate_sensitive_field(message)


@pytest.mark.parametrize(
    "newline",
    ["\n", "\r\n", "\r"],
)
def test_original_line_endings_preserved(
    newline: str,
) -> None:
    settings = Settings(_env_file=None)

    message = f"Application failure{newline}Additional diagnostic details"

    payload = json.dumps(
        {
            "severity": "ERROR",
            "message": message,
        }
    ).encode("utf-8")

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.JSON,
    )

    sanitized = LogSanitizer(settings).sanitize(normalized)

    assert sanitized.entries[0].message == message
    assert sanitized.redaction_count == 0


@pytest.mark.parametrize(
    "newline",
    ["\n", "\r\n", "\r"],
)
@pytest.mark.parametrize(
    "field",
    [
        "message",
        "exception",
        "service_name",
        "error_code",
        "correlation_id",
        "severity",
    ],
)
def test_fragmented_credentials_in_structured_fields(
    newline: str,
    field: str,
) -> None:
    settings = Settings(_env_file=None)

    document = {
        "message": "Application failure",
        "severity": "ERROR",
    }

    document[field] = f"password={newline}{CANARY}"

    payload = json.dumps(document).encode("utf-8")

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.JSON,
    )

    with pytest.raises(UnsafeLogContentError) as captured:
        LogSanitizer(settings).sanitize(normalized)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "newline",
    ["\n", "\r\n", "\r"],
)
def test_fragmented_source_name_rejected(
    newline: str,
) -> None:
    settings = Settings(_env_file=None)

    source_name = f"password={newline}{CANARY}"

    with pytest.raises(UnsafeLogContentError) as captured:
        LogSanitizer(settings).sanitize_source_name(source_name)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "newline",
    ["\n", "\r\n", "\r"],
)
def test_fragmented_text_events_rejected(
    newline: str,
) -> None:
    settings = Settings(_env_file=None)

    payload = (f"ERROR password={newline}{CANARY}").encode()

    normalized = LogNormalizer(settings).parse_and_normalize(
        payload,
        LogFormat.TEXT,
    )

    with pytest.raises(UnsafeLogContentError):
        LogSanitizer(settings).sanitize(normalized)
