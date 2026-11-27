import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.logs.security import validate_sensitive_field
from app.parsers.exceptions import UnsafeLogContentError

WHITESPACE = (
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


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


ASSIGNMENT_LABELS = (
    ("password", "="),
    ("api_key", ":"),
    ("access_token", "="),
    ("client_secret", ":"),
    (fullwidth("password"), "\uff1a"),
    (fullwidth("secret_key"), "\ufe66"),
)

AUTHORIZATION_SCHEMES = (
    "Bearer",
    "Basic",
    fullwidth("Bearer"),
    fullwidth("Basic"),
    "B\uff45arer",
    "B\uff41sic",
)

ASSIGNMENT_CASES = tuple(
    value
    for label, delimiter in ASSIGNMENT_LABELS
    for whitespace in WHITESPACE
    for value in (
        label + whitespace + delimiter,
        label + delimiter + whitespace,
        label + whitespace + delimiter + whitespace,
        label + delimiter + whitespace + '"',
    )
)

AUTHORIZATION_CASES = tuple(
    scheme + whitespace for scheme in AUTHORIZATION_SCHEMES for whitespace in WHITESPACE
)

UNSAFE_VALUES = ASSIGNMENT_CASES + AUTHORIZATION_CASES


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None)


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_incomplete_unicode_whitespace_field_rejected(
    value: str,
) -> None:
    with pytest.raises(
        UnsafeLogContentError,
        match="incomplete credential expression",
    ):
        validate_sensitive_field(value)


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_incomplete_unicode_whitespace_outbound_rejected(
    settings: Settings,
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError):
        validate_outbound_text(
            value,
            settings.log_max_metadata_chars,
        )


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_incomplete_unicode_whitespace_metadata_rejected(
    settings: Settings,
    value: str,
) -> None:
    sanitizer = LogSanitizer(settings)

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize_source_name(value)


@pytest.mark.parametrize("whitespace", WHITESPACE)
@pytest.mark.parametrize(
    ("left", "right"),
    (
        ("Database", "unavailable"),
        ("Service", "restored"),
        ("password", "validation completed"),
        ("Authorization", "configuration loaded"),
        ("\u63a5\u7d9a", "\u5931\u6557"),
        ("\u0645\u06cc\u200c\u0631\u0648\u062f", "service"),
    ),
)
def test_legitimate_unicode_whitespace_preserved(
    settings: Settings,
    whitespace: str,
    left: str,
    right: str,
) -> None:
    value = left + whitespace + right

    validate_sensitive_field(value)

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )

    sanitized, count = LogSanitizer(settings).sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


@pytest.mark.parametrize("whitespace", WHITESPACE)
@pytest.mark.parametrize(
    ("label", "delimiter"),
    ASSIGNMENT_LABELS,
)
def test_complete_redacted_assignment_preserved(
    settings: Settings,
    whitespace: str,
    label: str,
    delimiter: str,
) -> None:
    value = label + whitespace + delimiter + whitespace + "[REDACTED_SECRET]"

    validate_sensitive_field(value)

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )

    sanitized, count = LogSanitizer(settings).sanitize_source_name(value)

    assert sanitized == value
    assert count == 0


@pytest.mark.parametrize("whitespace", WHITESPACE)
@pytest.mark.parametrize("scheme", AUTHORIZATION_SCHEMES)
def test_complete_redacted_authorization_safe(
    settings: Settings,
    whitespace: str,
    scheme: str,
) -> None:
    value = scheme + whitespace + "[REDACTED_TOKEN]"

    validate_sensitive_field(value)

    validate_outbound_text(
        value,
        settings.log_max_metadata_chars,
    )
