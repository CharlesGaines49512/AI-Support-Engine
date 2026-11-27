import pytest

from app.core.config import Settings
from app.logs.outbound_security import (
    UnsafeOutboundEvidenceError,
    validate_outbound_text,
)
from app.logs.sanitizer import LogSanitizer
from app.security.sanitizer import sanitize_text

CANARY = "SYNTHETIC_AUTHORIZATION_CANARY"

AUTHORIZATION_SCHEMES = (
    "Bearer",
    "Basic",
    "\uff22\uff45\uff41\uff52\uff45\uff52",
    "\uff22\uff41\uff53\uff49\uff43",
    "B\uff45arer",
    "Be\uff41rer",
    "\uff22earer",
    "Beare\uff52",
    "B\uff41sic",
    "Ba\uff53ic",
    "\uff22asic",
    "Basi\uff43",
)

AUTHORIZATION_SEPARATORS = (
    " ",
    "  ",
    "\t",
    "\u00a0",
    "\u1680",
    "\u2003",
    "\u2009",
    "\u202f",
    "\u205f",
    "\u3000",
)

AUTHORIZATION_VALUES = tuple(
    (scheme, separator)
    for scheme in AUTHORIZATION_SCHEMES
    for separator in AUTHORIZATION_SEPARATORS
)


@pytest.mark.parametrize(
    ("scheme", "separator"),
    AUTHORIZATION_VALUES,
)
def test_unicode_authorization_redaction(
    scheme: str,
    separator: str,
) -> None:
    value = f"{scheme}{separator}{CANARY}"

    result = sanitize_text(value)

    assert CANARY not in result.text
    assert result.redaction_count == 1
    assert result.text == f"{scheme} [REDACTED_TOKEN]"

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize(
    ("scheme", "separator"),
    AUTHORIZATION_VALUES,
)
def test_unicode_authorization_outbound_rejection(
    scheme: str,
    separator: str,
) -> None:
    value = f"{scheme}{separator}{CANARY}"

    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    ("scheme", "separator"),
    AUTHORIZATION_VALUES,
)
def test_unicode_authorization_metadata_redaction(
    scheme: str,
    separator: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    value = f"{scheme}{separator}{CANARY}"

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == f"{scheme} [REDACTED_TOKEN]"
    assert count == 1


@pytest.mark.parametrize(
    ("scheme", "separator"),
    AUTHORIZATION_VALUES,
)
def test_unicode_authorization_idempotence(
    scheme: str,
    separator: str,
) -> None:
    value = f"{scheme}{separator}{CANARY}"

    first = sanitize_text(value)
    second = sanitize_text(first.text)

    assert CANARY not in first.text
    assert first.redaction_count == 1
    assert second.text == first.text
    assert second.redaction_count == 0

    validate_outbound_text(second.text, 2000)


@pytest.mark.parametrize(
    "scheme",
    AUTHORIZATION_SCHEMES,
)
def test_unicode_authorization_safe_marker(
    scheme: str,
) -> None:
    value = f"{scheme} [REDACTED_TOKEN]"

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize(
    "separator",
    AUTHORIZATION_SEPARATORS,
)
def test_unicode_diagnostic_text_preserved(
    separator: str,
) -> None:
    value = f"Authentication{separator}service unavailable."

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize(
    "separator",
    AUTHORIZATION_SEPARATORS,
)
def test_unicode_diagnostic_metadata_preserved(
    separator: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    value = f"Authentication{separator}service"

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0
