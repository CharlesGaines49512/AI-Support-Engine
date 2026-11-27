import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.logs.security import validate_sensitive_field
from app.parsers.exceptions import UnsafeLogContentError
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_COMBINED_UNICODE_CANARY"

AUTHORIZATION_SCHEMES = (
    "Bearer",
    "Basic",
    "\uff22\uff45\uff41\uff52\uff45\uff52",
    "\uff22\uff41\uff53\uff49\uff43",
    "B\uff45arer",
    "B\uff41sic",
)

JOINERS = (
    "\u200c",
    "\u200d",
)

SEPARATORS = (
    " ",
    "\t",
    "\u00a0",
    "\u2003",
    "\u3000",
)

AUTHORIZATION_CASES = tuple(
    f"{scheme[0]}{joiner}{scheme[1:]}{separator}{CANARY}"
    for scheme in AUTHORIZATION_SCHEMES
    for joiner in JOINERS
    for separator in SEPARATORS
)

PRESERVED_TEXT = (
    "\u0645\u06cc\u200c\u0631\u0648\u062f",
    "\u0646\u0645\u06cc\u200c\u0634\u0648\u062f",
    "\u06a9\u062a\u0627\u0628\u200c\u0647\u0627",
    "\u0915\u094d\u200d\u0937",
    "\u091c\u094d\u200d\u091e",
    "\u0915\u094d\u200c\u0937",
    "\U0001f469\u200d\U0001f4bb",
    "\U0001f468\u200d\U0001f469\u200d\U0001f467",
)

DIAGNOSTIC_CASES = tuple(
    f"Service {value}{separator}unavailable."
    for value in PRESERVED_TEXT
    for separator in SEPARATORS
)


@pytest.mark.parametrize("value", AUTHORIZATION_CASES)
def test_combined_authorization_field_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeLogContentError) as captured:
        validate_sensitive_field(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", AUTHORIZATION_CASES)
def test_combined_authorization_outbound_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", AUTHORIZATION_CASES)
def test_combined_authorization_metadata_rejection(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    with pytest.raises(UnsafeLogContentError) as captured:
        sanitizer.sanitize_source_name(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize("value", DIAGNOSTIC_CASES)
def test_combined_international_text_preserved(
    value: str,
) -> None:
    validate_sensitive_field(value)

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize("value", DIAGNOSTIC_CASES)
def test_combined_international_metadata_preserved(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0
