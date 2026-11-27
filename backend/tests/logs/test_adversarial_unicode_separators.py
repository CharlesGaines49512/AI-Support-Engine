import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_UNICODE_SEPARATOR_CANARY"

CREDENTIAL_LABEL_PARTS = (
    ("api", "key"),
    ("access", "token"),
    ("refresh", "token"),
    ("client", "secret"),
    ("secret", "key"),
)

UNICODE_SPACES = (
    "\u00a0",
    "\u1680",
    "\u2000",
    "\u2001",
    "\u2002",
    "\u2003",
    "\u2004",
    "\u2005",
    "\u2006",
    "\u2007",
    "\u2008",
    "\u2009",
    "\u200a",
    "\u202f",
    "\u205f",
    "\u3000",
)

COMPATIBILITY_DELIMITERS = (
    "\ufe55",
    "\ufe66",
)

COMPATIBILITY_LABELS = (
    "password",
    "passwd",
    "pwd",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret_key",
    "token",
    "secret",
)

ASSIGNMENTS = tuple(
    f"{left}{separator}{right}={CANARY}"
    for left, right in CREDENTIAL_LABEL_PARTS
    for separator in UNICODE_SPACES
) + tuple(
    f"{label}{delimiter}{CANARY}"
    for label in COMPATIBILITY_LABELS
    for delimiter in COMPATIBILITY_DELIMITERS
)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_unicode_separator_credential_redacted(
    value: str,
) -> None:
    result = sanitize_text(value)

    assert CANARY not in result.text
    assert result.redaction_count >= 1

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_unicode_separator_credential_rejected_outbound(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_unicode_separator_metadata_redacted(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized is not None
    assert CANARY not in sanitized
    assert count >= 1

    validate_outbound_text(sanitized, 2000)


@pytest.mark.parametrize("value", ASSIGNMENTS)
def test_unicode_separator_redaction_idempotent(
    value: str,
) -> None:
    first = sanitize_text(value)
    second = sanitize_text(first.text)

    assert CANARY not in first.text
    assert first.redaction_count >= 1

    assert second.text == first.text
    assert second.redaction_count == 0

    validate_outbound_text(second.text, 2000)


@pytest.mark.parametrize("separator", UNICODE_SPACES)
def test_unicode_diagnostic_spacing_preserved(
    separator: str,
) -> None:
    value = f"Database{separator}connection failed."

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize("separator", UNICODE_SPACES)
def test_unicode_metadata_spacing_preserved(
    separator: str,
) -> None:
    sanitizer = LogSanitizer(Settings())
    value = f"Database{separator}service"

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


@pytest.mark.parametrize(
    "value",
    (
        "Status\ufe55 completed",
        "Result\ufe66 successful",
        "Request \u2460 completed.",
        "Status: \uff2f\uff2b",
    ),
)
def test_ordinary_compatibility_characters_preserved(
    value: str,
) -> None:
    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)
