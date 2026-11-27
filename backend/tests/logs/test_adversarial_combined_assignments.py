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

CANARY = "SYNTHETIC_COMBINED_ASSIGNMENT_CANARY"

LABEL_PARTS = (
    ("api", "key"),
    ("access", "token"),
    ("refresh", "token"),
    ("client", "secret"),
    ("secret", "key"),
)

SEPARATORS = (
    "__",
    "_\u00a0",
    "\uff3f\u3000",
    "-\u2003_",
)

JOINERS = (
    "\u200c",
    "\u200d",
)

DELIMITERS = (
    ":",
    "\uff1d",
    "\ufe55",
    "\ufe66",
)


def fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if 0x21 <= ord(character) <= 0x7E else character
        for character in value
    )


COMBINED_LABELS = tuple(
    fullwidth(first) + separator + fullwidth(second)
    for first, second in LABEL_PARTS
    for separator in SEPARATORS
)

COMPATIBLE_ASSIGNMENTS = tuple(
    label + delimiter for label in COMBINED_LABELS for delimiter in DELIMITERS
)

JOINER_ASSIGNMENTS = tuple(
    label[0] + joiner + label[1:] + delimiter + CANARY
    for label in COMBINED_LABELS
    for joiner in JOINERS
    for delimiter in DELIMITERS
)

PRESERVATION_VALUES = tuple(
    fullwidth("service") + separator + fullwidth("status") + delimiter + "unavailable"
    for separator in SEPARATORS
    for delimiter in DELIMITERS
)


@pytest.mark.parametrize(
    "prefix",
    COMPATIBLE_ASSIGNMENTS,
)
def test_combined_assignment_redaction(
    prefix: str,
) -> None:
    result = sanitize_text(prefix + CANARY)

    assert result.text == prefix + "[REDACTED_SECRET]"
    assert result.redaction_count == 1

    validate_outbound_text(result.text, 2000)


@pytest.mark.parametrize(
    "prefix",
    COMPATIBLE_ASSIGNMENTS,
)
def test_combined_assignment_outbound_rejection(
    prefix: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(prefix + CANARY, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "prefix",
    COMPATIBLE_ASSIGNMENTS,
)
def test_combined_assignment_metadata_redaction(
    prefix: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(prefix + CANARY)

    assert sanitized == prefix + "[REDACTED_SECRET]"
    assert count == 1


@pytest.mark.parametrize(
    "prefix",
    COMPATIBLE_ASSIGNMENTS,
)
def test_combined_assignment_idempotence(
    prefix: str,
) -> None:
    first = sanitize_text(prefix + CANARY)
    second = sanitize_text(first.text)

    assert first.redaction_count == 1
    assert CANARY not in first.text
    assert second.text == first.text
    assert second.redaction_count == 0


@pytest.mark.parametrize(
    "value",
    JOINER_ASSIGNMENTS,
)
def test_combined_joiner_field_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeLogContentError) as captured:
        validate_sensitive_field(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "value",
    JOINER_ASSIGNMENTS,
)
def test_combined_joiner_outbound_rejection(
    value: str,
) -> None:
    with pytest.raises(UnsafeOutboundEvidenceError) as captured:
        validate_outbound_text(value, 2000)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "value",
    JOINER_ASSIGNMENTS,
)
def test_combined_joiner_metadata_rejection(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    with pytest.raises(UnsafeLogContentError) as captured:
        sanitizer.sanitize_source_name(value)

    assert CANARY not in str(captured.value)


@pytest.mark.parametrize(
    "value",
    PRESERVATION_VALUES,
)
def test_combined_diagnostic_preservation(
    value: str,
) -> None:
    validate_sensitive_field(value)

    result = sanitize_text(value)

    assert result.text == value
    assert result.redaction_count == 0

    validate_outbound_text(value, 2000)


@pytest.mark.parametrize(
    "value",
    PRESERVATION_VALUES,
)
def test_combined_metadata_preservation(
    value: str,
) -> None:
    sanitizer = LogSanitizer(Settings())

    sanitized, count = sanitizer.sanitize_source_name(value)

    assert sanitized == value
    assert count == 0
