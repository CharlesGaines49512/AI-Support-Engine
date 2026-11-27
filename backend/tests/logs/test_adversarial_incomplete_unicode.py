import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.logs.security import validate_sensitive_field
from app.parsers.exceptions import UnsafeLogContentError

LABELS = (
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
    "authorization",
    "credential",
)


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


COMPATIBLE_LABELS = tuple(fullwidth(label) for label in LABELS)

DELIMITERS = (
    ":",
    "=",
    "\uff1a",
    "\uff1d",
    "\ufe55",
    "\ufe66",
)

INCOMPLETE_VALUES = tuple(
    label + delimiter for label in COMPATIBLE_LABELS for delimiter in DELIMITERS
)

COMPOUND_LABELS = tuple(
    label.replace("_", separator)
    for label in LABELS
    if "_" in label
    for separator in (
        "__",
        "  ",
        "_\u00a0",
        "\uff3f\u3000",
    )
)

COMPOUND_VALUES = tuple(
    label + delimiter for label in COMPOUND_LABELS for delimiter in (":", "\ufe66")
)

ALL_INCOMPLETE = INCOMPLETE_VALUES + COMPOUND_VALUES

DIAGNOSTIC_VALUES = (
    "Database connection:",
    "Authentication service:",
    "Credential validation completed.",
    "Password policy enabled.",
    "Token renewal scheduled.",
    "Service status\uff1a",
    "Database status\ufe55",
    "Request status\ufe66",
    "\u63a5\u7d9a\u72b6\u614b\uff1a",
    "\u30b5\u30fc\u30d3\u30b9\uff1a",
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\U0001f469\u200d\U0001f4bb",
)


@pytest.mark.parametrize("value", ALL_INCOMPLETE)
def test_incomplete_unicode_field_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        validate_sensitive_field(value)


@pytest.mark.parametrize("value", ALL_INCOMPLETE)
def test_incomplete_unicode_outbound_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError):
        validate_outbound_text(value, 2000)


@pytest.mark.parametrize("value", ALL_INCOMPLETE)
def test_incomplete_unicode_metadata_rejection(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize_source_name(value)


@pytest.mark.parametrize("value", COMPATIBLE_LABELS)
def test_standalone_unicode_label_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeLogContentError):
        validate_sensitive_field(value)


@pytest.mark.parametrize("value", COMPATIBLE_LABELS)
def test_standalone_unicode_outbound_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError):
        validate_outbound_text(value, 2000)


@pytest.mark.parametrize("value", COMPATIBLE_LABELS)
def test_standalone_unicode_metadata_rejection(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    with pytest.raises(UnsafeLogContentError):
        sanitizer.sanitize_source_name(value)


@pytest.mark.parametrize("value", DIAGNOSTIC_VALUES)
def test_incomplete_unicode_diagnostic_preservation(
    value: str,
) -> None:
    validate_sensitive_field(value)
    validate_outbound_text(value, 2000)


@pytest.mark.parametrize("value", DIAGNOSTIC_VALUES)
def test_incomplete_unicode_metadata_preservation(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0
