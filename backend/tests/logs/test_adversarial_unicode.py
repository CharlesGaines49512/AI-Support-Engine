import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_UNICODE_SECURITY_CANARY"

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
    "token",
    "secret",
)


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0)
        if 33 <= ord(character) <= 126
        else "\u3000"
        if character == " "
        else character
        for character in value
    )


COMPATIBILITY_ASSIGNMENTS = tuple(
    f"{fullwidth(label)}{separator}{CANARY}"
    for label in LABELS
    for separator in ("=", ":", "\uff1d", "\uff1a")
) + tuple(
    f"{label}{separator}{CANARY}"
    for label in LABELS
    for separator in ("\uff1d", "\uff1a")
)


SAFE_MESSAGES = (
    "Diagnostic message: caf\u00e9",
    "Diagnostic message: cafe\u0301",
    "\u6570\u636e\u5e93\u8fde\u63a5\u5931\u8d25",
    "\u30b5\u30fc\u30d0\u30fc\u30a8\u30e9\u30fc",
    "\uc11c\ubc84 \uc624\ub958",
    "\u041e\u0448\u0438\u0431\u043a\u0430",
    "\u062e\u0637\u0623 \u0627\u0644\u062e\u0627\u062f\u0645",
    "Service restarted \U0001f680",
    "Temperature: 25\u00b0C",
    "Status: \uff2f\uff2b",
    "Request \u2460 completed.",
    "Password reset completed.",
    "API key rotation completed.",
    "Database connection failed.",
    "Processing\u00a0completed.",
    "Processing\u3000completed.",
)


@pytest.mark.parametrize(
    "value",
    COMPATIBILITY_ASSIGNMENTS,
)
def test_compatibility_credential_redacted(
    value: str,
) -> None:
    result = sanitize_text(value)

    assert CANARY not in result.text
    assert result.redaction_count >= 1

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize(
    "value",
    COMPATIBILITY_ASSIGNMENTS,
)
def test_compatibility_credential_rejected_outbound(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "value",
    COMPATIBILITY_ASSIGNMENTS,
)
def test_compatibility_source_metadata_redacted(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized is not None
    assert CANARY not in sanitized
    assert count >= 1

    validate_outbound_text(sanitized, 2000)


@pytest.mark.parametrize(
    "value",
    SAFE_MESSAGES,
)
def test_unicode_diagnostic_text_preserved(
    value: str,
) -> None:
    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize(
    "value",
    SAFE_MESSAGES,
)
def test_unicode_source_metadata_preserved(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


@pytest.mark.parametrize("label", LABELS)
def test_compatibility_redaction_idempotent(
    label: str,
) -> None:
    original = f"{fullwidth(label)}\uff1d{CANARY}"

    first = sanitize_text(original)
    second = sanitize_text(first.text)

    assert CANARY not in first.text
    assert first.redaction_count >= 1

    assert second.text == first.text
    assert second.redaction_count == 0

    validate_outbound_text(second.text, 2000)
